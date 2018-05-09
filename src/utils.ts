import nacl from 'tweetnacl'

export const SIGNATURE_LENGTH = nacl.sign.signatureLength
export const PRIVATE_KEY_LENGTH = nacl.sign.secretKeyLength
export const PUBLIC_KEY_LENGTH = nacl.sign.publicKeyLength

/**
 * Generates a private key for signing.
 * @returns 64-byte private key.
 */
export function generatePrivateKey(): Uint8Array {
  const pair = nacl.sign.keyPair()
  return pair.secretKey
}

/**
 * Generates the public key that corresponds to the given private key.
 * @param privateKey 64-byte private key.
 * @returns 32-byte public key.
 */
export function publicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
  const pair = nacl.sign.keyPair.fromSecretKey(privateKey)
  return pair.publicKey
}

/**
 * Encodes bytes to a base64 string.
 * @param bytes Array of bytes to encode to string.
 * @returns base64 encoded string.
 */
export function Uint8ArrayToB64(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString('base64')
}

/**
 * Decodes bytes from a base64 string.
 * @param s String to decode.
 * @returns Array of bytes.
 */
export function B64ToUint8Array(s: string): Uint8Array {
  return Buffer.from(s, 'base64')
}
