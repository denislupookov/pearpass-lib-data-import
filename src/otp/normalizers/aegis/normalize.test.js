import { normalizeAegisDb } from './normalize'

// `info` is replaced wholesale when provided, so tests can omit fields to
// exercise the normalizer's own defaults.
const makeEntry = ({
  type = 'totp',
  name = 'alice@example.com',
  issuer = 'GitHub',
  info
} = {}) => ({
  type,
  uuid: 'u1',
  name,
  issuer,
  note: '',
  favorite: false,
  icon: null,
  info: info ?? {
    secret: 'JBSWY3DPEHPK3PXP',
    algo: 'SHA1',
    digits: 6,
    period: 30
  }
})

describe('normalizeAegisDb', () => {
  it('maps a TOTP entry to an OTPRecord', () => {
    const records = normalizeAegisDb({ entries: [makeEntry()] })
    expect(records).toHaveLength(1)
    expect(records[0]).toMatchObject({
      type: 'TOTP',
      label: 'alice@example.com',
      issuer: 'GitHub',
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
    expect(records[0].raw).toBeDefined()
    expect(records[0]).not.toHaveProperty('counter')
  })

  it('maps an HOTP entry with counter instead of period', () => {
    const records = normalizeAegisDb({
      entries: [
        makeEntry({
          type: 'hotp',
          name: 'bob',
          issuer: 'Bank',
          info: {
            secret: 'JBSWY3DPEHPK3PXP',
            algo: 'SHA256',
            digits: 8,
            counter: 5
          }
        })
      ]
    })
    expect(records[0]).toMatchObject({
      type: 'HOTP',
      algorithm: 'SHA256',
      digits: 8,
      counter: 5
    })
    expect(records[0]).not.toHaveProperty('period')
  })

  it('skips unsupported types (e.g. steam) and entries without a secret', () => {
    const records = normalizeAegisDb({
      entries: [
        makeEntry({
          type: 'steam',
          info: { secret: 'X', algo: 'SHA1', digits: 5, period: 30 }
        }),
        makeEntry({
          info: { secret: '', algo: 'SHA1', digits: 6, period: 30 }
        }),
        makeEntry()
      ]
    })
    expect(records).toHaveLength(1)
    expect(records[0].type).toBe('TOTP')
  })

  it('applies defaults for missing algo/digits/period', () => {
    const records = normalizeAegisDb({
      entries: [makeEntry({ info: { secret: 'JBSWY3DPEHPK3PXP' } })]
    })
    expect(records[0]).toMatchObject({
      algorithm: 'SHA1',
      digits: 6,
      period: 30
    })
  })

  it('skips a present-but-invalid algorithm (never silently coerces to SHA1)', () => {
    const records = normalizeAegisDb({
      entries: [
        makeEntry({
          info: {
            secret: 'JBSWY3DPEHPK3PXP',
            algo: 'MD5',
            digits: 6,
            period: 30
          }
        }),
        makeEntry() // a valid entry alongside the bad one
      ]
    })
    // bad-algo entry skipped, valid entry kept — the whole import isn't aborted
    expect(records).toHaveLength(1)
    expect(records[0].algorithm).toBe('SHA1')
  })

  it('skips an entry whose secret is not a string', () => {
    const records = normalizeAegisDb({
      entries: [
        makeEntry({
          info: { secret: 12345, algo: 'SHA1', digits: 6, period: 30 }
        })
      ]
    })
    expect(records).toEqual([])
  })

  it('returns [] for missing or empty entries', () => {
    expect(normalizeAegisDb({})).toEqual([])
    expect(normalizeAegisDb({ entries: [] })).toEqual([])
    expect(normalizeAegisDb(null)).toEqual([])
  })
})
