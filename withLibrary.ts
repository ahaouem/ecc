const crypto = require("crypto");

function generateECDHKeyPair() {
  const ecdh = crypto.createECDH("prime256v1");
  const publicKey = ecdh.generateKeys();
  return { ecdh, publicKey };
}

function encryptWithAES(key, iv, plaintext) {
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return encrypted;
}

function decryptWithAES(key, iv, ciphertext) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(ciphertext, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

const alice = generateECDHKeyPair();
const bob = generateECDHKeyPair();

const aliceSharedSecret = alice.ecdh.computeSecret(bob.publicKey);
const bobSharedSecret = bob.ecdh.computeSecret(alice.publicKey);

const aesKey = aliceSharedSecret.slice(0, 32);
const iv = crypto.randomBytes(16);

const message = "Hello, World!";
const encryptedMessage = encryptWithAES(aesKey, iv, message);
console.log("Encrypted message:", encryptedMessage);

const decryptedMessage = decryptWithAES(aesKey, iv, encryptedMessage);
console.log("Decrypted message:", decryptedMessage);
