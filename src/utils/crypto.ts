// Client-Side Cryptography Utilities using Web Crypto API
// This code runs only in the browser (client-side)

/**
 * Converts a string into a Uint8Array (UTF-8 bytes)
 */
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts a Uint8Array into a base64 string
 */
function bytesToBase64(bytes: Uint8Array): string {
  const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binString);
}

/**
 * Converts a base64 string into a Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  return Uint8Array.from(binString, (char) => char.charCodeAt(0));
}

/**
 * Derives both the Encryption Key and the Authentication Hash from the master password and email.
 * This implements the 512-bit key derivation split.
 * - PBKDF2 with SHA-256, 100,000 iterations.
 * - Salt is derived from the user's email.
 * - Output is 64 bytes (512 bits):
 *   - Bytes 0-31: Master Encryption Key (for local AES-GCM)
 *   - Bytes 32-63: Client Authentication Key (hex-encoded to send to server)
 */
export async function deriveKeys(password: string, email: string): Promise<{
  encryptionKey: CryptoKey;
  authHash: string;
  keyDerivationSalt: string;
}> {
  if (typeof window === 'undefined') {
    throw new Error('Cryptography functions can only be executed in the browser.');
  }

  const subtle = window.crypto.subtle;
  
  // Create a unique salt using the user's email to prevent rainbow table attacks
  const saltString = `safepass-salt-v1-${email.toLowerCase().trim()}`;
  const saltBytes = stringToBytes(saltString);

  // Import the raw master password as a key-deriving-key
  const passwordBytes = stringToBytes(password);
  const baseKey = await subtle.importKey(
    'raw',
    passwordBytes as any,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );

  // Derive 512 bits (64 bytes)
  const derivedBits = await subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes as any,
      iterations: 100000,
      hash: 'SHA-256',
    },
    baseKey,
    512
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const encryptionKeyBytes = derivedBytes.slice(0, 32);
  const authKeyBytes = derivedBytes.slice(32, 64);

  // Import the encryption key bytes into a CryptoKey object for AES-GCM
  const encryptionKey = await subtle.importKey(
    'raw',
    encryptionKeyBytes as any,
    { name: 'AES-GCM', length: 256 },
    false, // key is not extractable (highly secure!)
    ['encrypt', 'decrypt']
  );

  // Convert the authentication key to a hex string to send to the server
  const authHash = Array.from(authKeyBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return {
    encryptionKey,
    authHash,
    keyDerivationSalt: saltString,
  };
}

/**
 * Encrypts plaintext using AES-GCM-256 with the derived Encryption Key.
 * Generates a random 12-byte initialization vector (IV).
 * Returns base64 strings of the ciphertext and IV.
 */
export async function encryptText(
  plaintext: string,
  encryptionKey: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  if (typeof window === 'undefined') {
    throw new Error('Cryptography functions can only be executed in the browser.');
  }

  const subtle = window.crypto.subtle;
  const plaintextBytes = stringToBytes(plaintext);
  
  // AES-GCM requires a 12-byte IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as any,
    },
    encryptionKey,
    plaintextBytes as any
  );

  const ciphertextBytes = new Uint8Array(ciphertextBuffer);

  return {
    ciphertext: bytesToBase64(ciphertextBytes),
    iv: bytesToBase64(iv),
  };
}

/**
 * Decrypts AES-GCM-256 encrypted base64 ciphertext using the derived Encryption Key and IV.
 */
export async function decryptText(
  ciphertext: string,
  iv: string,
  encryptionKey: CryptoKey
): Promise<string> {
  if (typeof window === 'undefined') {
    throw new Error('Cryptography functions can only be executed in the browser.');
  }

  const subtle = window.crypto.subtle;
  const ciphertextBytes = base64ToBytes(ciphertext);
  const ivBytes = base64ToBytes(iv);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: ivBytes as any,
    },
    encryptionKey,
    ciphertextBytes as any
  );

  return new TextDecoder().decode(decryptedBuffer);
}
