import crypto from 'node:crypto'
import { base64UrlDecode, base64UrlEncode } from './codec'

describe('codec', () => {
  test.each(Array.from({ length: 32 }, (_, i) => i))(
    'base64url (buffer size %d)',
    bufferSize => {
      const bytes = crypto.randomBytes(bufferSize)
      const buffer = new Uint8Array(crypto.randomBytes(bufferSize))
      // Ensure we have the special two chars
      buffer[0] = 0xff
      buffer[2] = 0xfe
      const b64Node = bytes.toString('base64url')
      expect(base64UrlDecode(base64UrlEncode(buffer))).toEqual(buffer)
      expect(base64UrlEncode(base64UrlDecode(b64Node))).toEqual(b64Node)
    }
  )
})
