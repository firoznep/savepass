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
  const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join(
    "",
  );
  return btoa(binString);
}

/**
 * Converts a base64 string into a Uint8Array
 */
function base64ToBytes(base64: string): Uint8Array {
  const binString = atob(base64);
  return Uint8Array.from(binString, (char) => char.charCodeAt(0));
}

function getSubtleCrypto(): SubtleCrypto {
  if (typeof window === "undefined") {
    throw new Error(
      "Cryptography functions can only be executed in the browser.",
    );
  }

  if (!window.isSecureContext || !window.crypto?.subtle) {
    throw new Error(
      "Secure browser cryptography is unavailable. Open this app over HTTPS, or use localhost for development.",
    );
  }

  return window.crypto.subtle;
}

async function importAesGcmKey(rawKeyBytes: Uint8Array): Promise<CryptoKey> {
  return getSubtleCrypto().importKey(
    "raw",
    rawKeyBytes as any,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function generateVaultKey(): Promise<{
  key: CryptoKey;
  keyBytes: Uint8Array;
}> {
  const keyBytes = window.crypto.getRandomValues(new Uint8Array(32));
  const key = await importAesGcmKey(keyBytes);
  return { key, keyBytes };
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
export async function deriveKeys(
  password: string,
  email: string,
): Promise<{
  encryptionKey: CryptoKey;
  authHash: string;
  keyDerivationSalt: string;
  encryptionKeyBytes: Uint8Array;
}> {
  const subtle = getSubtleCrypto();

  // Create a unique salt using the user's email to prevent rainbow table attacks
  const saltString = `safepass-salt-v1-${email.toLowerCase().trim()}`;
  const saltBytes = stringToBytes(saltString);

  // Import the raw master password as a key-deriving-key
  const passwordBytes = stringToBytes(password);
  const baseKey = await subtle.importKey(
    "raw",
    passwordBytes as any,
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"],
  );

  // Derive 512 bits (64 bytes)
  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes as any,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    512,
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const encryptionKeyBytes = derivedBytes.slice(0, 32);
  const authKeyBytes = derivedBytes.slice(32, 64);

  // Import the encryption key bytes into a CryptoKey object for AES-GCM
  const encryptionKey = await subtle.importKey(
    "raw",
    encryptionKeyBytes as any,
    { name: "AES-GCM", length: 256 },
    false, // key is not extractable (highly secure!)
    ["encrypt", "decrypt"],
  );

  // Convert the authentication key to a hex string to send to the server
  const authHash = Array.from(authKeyBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    encryptionKey,
    authHash,
    keyDerivationSalt: saltString,
    encryptionKeyBytes,
  };
}

/**
 * Encrypts plaintext using AES-GCM-256 with the derived Encryption Key.
 * Generates a random 12-byte initialization vector (IV).
 * Returns base64 strings of the ciphertext and IV.
 */
export async function encryptText(
  plaintext: string,
  encryptionKey: CryptoKey,
): Promise<{ ciphertext: string; iv: string }> {
  const subtle = getSubtleCrypto();
  const plaintextBytes = stringToBytes(plaintext);

  // AES-GCM requires a 12-byte IV
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as any,
    },
    encryptionKey,
    plaintextBytes as any,
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
  encryptionKey: CryptoKey,
): Promise<string> {
  const subtle = getSubtleCrypto();
  const ciphertextBytes = base64ToBytes(ciphertext);
  const ivBytes = base64ToBytes(iv);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivBytes as any,
    },
    encryptionKey,
    ciphertextBytes as any,
  );

  return new TextDecoder().decode(decryptedBuffer);
}

// Export helpers for use by recovery flow
export { stringToBytes, bytesToBase64, base64ToBytes };

/**
 * Derive recovery keys from a user-provided recovery code and email.
 * Returns the raw derived AES key bytes too so the client can wrap/unwrap the master key.
 */
export async function deriveRecoveryKeys(
  recoveryCode: string,
  email: string,
): Promise<{
  encryptionKey: CryptoKey;
  encryptionKeyBytes: Uint8Array;
  authHash: string;
  keyDerivationSalt: string;
}> {
  const subtle = getSubtleCrypto();

  const saltString = `safepass-recovery-salt-v1-${email.toLowerCase().trim()}`;
  const saltBytes = stringToBytes(saltString);

  const codeBytes = stringToBytes(recoveryCode);
  const baseKey = await subtle.importKey(
    "raw",
    codeBytes as any,
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"],
  );

  const derivedBits = await subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes as any,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    512,
  );

  const derivedBytes = new Uint8Array(derivedBits);
  const encryptionKeyBytes = derivedBytes.slice(0, 32);
  const authKeyBytes = derivedBytes.slice(32, 64);

  const encryptionKey = await subtle.importKey(
    "raw",
    encryptionKeyBytes as any,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const authHash = Array.from(authKeyBytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    encryptionKey,
    encryptionKeyBytes,
    authHash,
    keyDerivationSalt: saltString,
  };
}

/**
 * Wrap the raw master key bytes (base64) with the provided recovery CryptoKey.
 * Returns {ciphertext, iv} which can be safely stored on the server.
 */
export async function wrapMasterKeyWithRecovery(
  recoveryKey: CryptoKey,
  masterKeyBytesBase64: string,
) {
  return encryptText(masterKeyBytesBase64, recoveryKey);
}

/**
 * Unwrap the wrapped master key ciphertext using the recovery key.
 * Returns {key: CryptoKey, bytes: Uint8Array}
 */
export async function unwrapMasterKeyWithRecovery(
  recoveryKey: CryptoKey,
  ciphertext: string,
  iv: string,
) {
  const base64 = await decryptText(ciphertext, iv, recoveryKey);
  const bytes = base64ToBytes(base64);
  const key = await getSubtleCrypto().importKey(
    "raw",
    bytes as any,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, bytes };
}

/**
 * Wrap the raw vault key bytes (base64) with the password-derived key.
 */
export async function wrapVaultKeyWithPassword(
  passwordKey: CryptoKey,
  rawVaultKeyBase64: string,
) {
  return encryptText(rawVaultKeyBase64, passwordKey);
}

/**
 * Unwrap the password-wrapped vault key ciphertext back into the raw vault key.
 */
export async function unwrapVaultKeyWithPassword(
  passwordKey: CryptoKey,
  ciphertext: string,
  iv: string,
) {
  const base64 = await decryptText(ciphertext, iv, passwordKey);
  const bytes = base64ToBytes(base64);
  const key = await getSubtleCrypto().importKey(
    "raw",
    bytes as any,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { key, bytes };
}
