import { detectProvider } from './detectProvider.js'
import { OTP_PROVIDERS, STATUS } from '../constants.js'
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
 * Normalizes OTP URI/QR imports into OTPRecord[].
 *
 * Accepts one or more decoded QR/URI strings and auto-detects the format from
 * the URI scheme: Google Authenticator migration URIs (`otpauth-migration://`)
 * and standard `otpauth://` URIs. For Google batch exports, pass all QR payloads
 * together so partial batches can be detected.
 *
 * File-based authenticator exports (e.g. Aegis, Proton) are handled by their own
 * dedicated handlers — this stays a focused URI normalization layer.
 *
 * @param {string | string[]} input - OTP URI string(s)
 * @returns {NormalizeResult}
 */
export function normalizeImport(input) {
  const uris = Array.isArray(input) ? input : [input]

  if (uris.length === 0 || uris[0] === undefined || uris[0] === null) {
    throw new Error('normalizeImport: input must not be empty')
  }

  const provider = detectProvider(uris[0])

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

  throw new Error('normalizeImport: unsupported or unrecognized input format')
}
