export function base64UrlEncode(input: Uint8Array): string {
  return (
    window
      .btoa(String.fromCharCode(...input))
      // Convert to base64url
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/={1,2}$/, '')
  )
}

export function base64UrlDecode(input: string): Uint8Array {
  return new Uint8Array(
    // convert base64url to base64 for atob
    window
      .atob(input.replace(/-/g, '+').replace(/_/g, '/'))
      .split('')
      .map(x => x.charCodeAt(0))
  )
}
