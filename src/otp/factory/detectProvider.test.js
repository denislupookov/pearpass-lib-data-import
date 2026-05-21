import { detectProvider } from './detectProvider'

describe('detectProvider', () => {
  it('returns google-migration for otpauth-migration:// URIs', () => {
    expect(detectProvider('otpauth-migration://offline?data=abc')).toBe(
      'google-migration'
    )
  })

  it('returns otp-uri for otpauth:// URIs', () => {
    expect(detectProvider('otpauth://totp/alice?secret=ABC')).toBe('otp-uri')
  })

  it('returns unknown for unrecognised strings (including JSON file content)', () => {
    expect(detectProvider('https://example.com')).toBe('unknown')
    expect(detectProvider('')).toBe('unknown')
    expect(detectProvider('not-a-uri')).toBe('unknown')
    // File-based providers (e.g. Aegis JSON) are not sniffed here — they are
    // selected explicitly via normalizeImport(input, { provider }).
    expect(
      detectProvider(JSON.stringify({ header: {}, db: { entries: [] } }))
    ).toBe('unknown')
  })

  it('returns unknown for non-string input', () => {
    expect(detectProvider(null)).toBe('unknown')
    expect(detectProvider(undefined)).toBe('unknown')
    expect(detectProvider(42)).toBe('unknown')
    expect(detectProvider({})).toBe('unknown')
  })
})
