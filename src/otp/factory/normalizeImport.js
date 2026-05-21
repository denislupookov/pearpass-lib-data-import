import { detectProvider } from './detectProvider.js'
import { OTP_PROVIDERS, STATUS } from '../constants.js'
import { decodeAegisVault } from '../normalizers/aegis/decodeAegis.js'
import { normalizeAegisDb } from '../normalizers/aegis/normalize.js'
import { aggregateBatches } from '../normalizers/google/batch.js'
import { decodeMigrationUri } from '../normalizers/google/decodeMigration.js'
import { normalizeGooglePayload } from '../normalizers/google/normalize.js'
import { parseOtpUri } from '../shared/parseOtpUri.js'

/**
 * @typedef {import('../interfaces/OTPRecord.js').OTPRecord} OTPRecord
 *
 * @typedef {{ status: 'complete', records: OTPRecord[] }} NormalizeComplete
 * @typedef {{ status: 'incomplete-batch', expected: number, received: number, batchId: number }} NormalizeIncomplete
 * @typedef {NormalizeComplete | NormalizeIncomplete} NormalizeResult
 */

/**
 * Provider-agnostic entry point for importing OTP records.
 *
 * Accepts one or more decoded QR/URI strings, or the contents of a supported
 * file export (e.g. Aegis JSON). For QR/URI inputs the provider is auto-detected
 * from the scheme; for file-based providers the caller passes `options.provider`
 * (the import UI already knows which source the user picked).
 *
 * For Google Authenticator batch exports, pass all QR payloads together. For
 * encrypted Aegis exports, pass the password via `options.password`.
 *
 * @param {string | string[]} input - OTP URI string(s) or a file's contents
 * @param {{ provider?: string, password?: string }} [options]
 * @returns {NormalizeResult}
 */
export function normalizeImport(input, options = {}) {
  const uris = Array.isArray(input) ? input : [input]

  if (uris.length === 0 || uris[0] === undefined || uris[0] === null) {
    throw new Error('normalizeImport: input must not be empty')
  }

  const provider = options.provider ?? detectProvider(uris[0])

  if (provider === OTP_PROVIDERS.googleMigration) {
    const payloads = uris.map(decodeMigrationUri)
    const batchResult = aggregateBatches(payloads)

    if (batchResult.status !== STATUS.ready) {
      return batchResult
    }

    const records = normalizeGooglePayload({
      otpParameters: batchResult.otpParameters
    })
    return { status: STATUS.complete, records }
  }

  if (provider === OTP_PROVIDERS.otpUri) {
    const records = uris.map(parseOtpUri)
    return { status: STATUS.complete, records }
  }

  if (provider === OTP_PROVIDERS.aegis) {
    const db = decodeAegisVault(uris[0], options.password)
    const records = normalizeAegisDb(db)
    return { status: STATUS.complete, records }
  }

  throw new Error(`normalizeImport: unsupported or unrecognized input format`)
}
