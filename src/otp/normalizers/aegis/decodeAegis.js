import { decryptAegisVault } from './decrypt.js'

/**
 * Decodes an Aegis export to its plaintext `db` object — the Aegis analogue of
 * `decodeMigrationUri` for Google (the decode step before normalization).
 *
 * Handles JSON parsing and, for encrypted exports, decryption. The resulting
 * `db` is passed to `normalizeAegisDb` by the import factory.
 *
 * @param {string | Object} fileContent - raw Aegis .json content, or the parsed object
 * @param {string} [password] - required for encrypted exports
 * @returns {{ version?: number, entries?: Object[] }} the decrypted db
 * @throws {Error} on malformed input, missing/incorrect password, or biometric-only export
 */
export function decodeAegisVault(fileContent, password) {
  let json
  try {
    json =
      typeof fileContent === 'string' ? JSON.parse(fileContent) : fileContent
  } catch {
    throw new Error('Invalid Aegis export: not valid JSON')
  }

  if (!json || typeof json !== 'object') {
    throw new Error('Invalid Aegis export: expected a JSON object')
  }

  // Encrypted exports serialize `db` as a base64 string and fill header.slots.
  if (typeof json.db === 'string') {
    return decryptAegisVault(json, password)
  }

  if (!json.db || typeof json.db !== 'object') {
    throw new Error('Invalid Aegis export: missing "db"')
  }

  return json.db
}
