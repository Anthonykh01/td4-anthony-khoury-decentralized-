import { webcrypto } from "crypto";

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};

export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  return await webcrypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: {name: "SHA-256"},
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
  if (!key) return null;
  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exported);
}

export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const key = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "spki",
    key,
    {
      name: "RSA-OAEP",
      hash: {name: "SHA-256"},
    },
    true,
    ["encrypt"]
  );
}

export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const key = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "pkcs8",
    key,
    {
      name: "RSA-OAEP",
      hash: {name: "SHA-256"},
    },
    true,
    ["decrypt"]
  );
}

export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const data = base64ToArrayBuffer(b64Data);
  const publicKey = await importPubKey(strPublicKey);
  const encrypted = await webcrypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    publicKey,
    data
  );
  return arrayBufferToBase64(encrypted);
}

export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const encrypted = base64ToArrayBuffer(data);
  const decrypted = await webcrypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encrypted
  );
  return arrayBufferToBase64(decrypted);
}

export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
    {
      name: 'AES-CBC',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exported = await webcrypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(exported);
}

export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const key = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    "raw",
    key,
    {
      name: "AES-CBC",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  const dataUint8Array = new TextEncoder().encode(data);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await webcrypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    key,
    dataUint8Array
  );
  const concatenated = new Uint8Array([...iv, ...new Uint8Array(encrypted)]);
  return arrayBufferToBase64(concatenated.buffer);
}

export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  const key = await importSymKey(strKey);
  const encrypted = base64ToArrayBuffer(encryptedData);
  const iv = encrypted.slice(0, 16);
  const decrypted = await webcrypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    key,
    encrypted.slice(16)
  );
  return new TextDecoder().decode(decrypted);
}
