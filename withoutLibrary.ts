import * as crypto from "crypto";

export function keyPair(): { publicKey: string; privateKey: string } {
  const a: bigint = 0n;
  const b: bigint = 7n;
  const p: bigint = 2n ** 256n - 2n ** 32n - 977n;
  const n: bigint =
    115792089237316195423570985008687907852837564279074904382605163141518161494337n;

  const g = {
    x: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
    y: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  };

  function modinv(a: bigint, m: bigint = p): bigint {
    let m0: bigint = m;
    let y: bigint = 0n;
    let x: bigint = 1n;

    if (m === 1n) return 0n;

    while (a > 1n) {
      let q: bigint = a / m;
      let t: bigint = m;

      m = a % m;
      a = t;
      t = y;

      y = x - q * y;
      x = t;
    }

    if (x < 0n) x += m0;

    return x;
  }

  function double(point: { x: bigint; y: bigint }): { x: bigint; y: bigint } {
    let slope: bigint = ((3n * point.x ** 2n + a) * modinv(2n * point.y)) % p;
    let x: bigint = (slope ** 2n - 2n * point.x) % p;
    let y: bigint = (slope * (point.x - x) - point.y) % p;

    return { x, y };
  }

  function add(
    p1: { x: bigint; y: bigint },
    p2: { x: bigint; y: bigint }
  ): { x: bigint; y: bigint } {
    if (p1.x === p2.x && p1.y === p2.y) return double(p1);

    let slope: bigint = ((p1.y - p2.y) * modinv(p1.x - p2.x, p)) % p;
    let x: bigint = (slope ** 2n - p1.x - p2.x) % p;
    let y: bigint = (slope * (p1.x - x) - p1.y) % p;

    return { x, y };
  }

  function multiply(k: bigint, point = g): { x: bigint; y: bigint } {
    let result: { x: bigint; y: bigint } | null = null;
    let addend = point;

    while (k > 0n) {
      if (k & 1n) {
        result = result ? add(result, addend) : addend;
      }
      addend = double(addend);
      k >>= 1n;
    }

    return result!;
  }

  let k: bigint;
  do {
    k = BigInt("0x" + crypto.randomBytes(32).toString("hex"));
  } while (k >= n || k < 1n);

  let point = multiply(k);
  let x = point.x.toString(16).padStart(64, "0");
  let y = point.y.toString(16).padStart(64, "0");
  let prefix: string = point.y % 2n === 0n ? "02" : "03";
  let publicKeyCompressed: string = prefix + x;

  return {
    publicKey: publicKeyCompressed,
    privateKey: k.toString(16).padStart(64, "0"),
  };
}
function bigintToBuffer(bi) {
  return Buffer.from(bi.toString(16).padStart(64, "0"), "hex");
}

function xorEncrypt(key, plaintext) {
  const keyBuffer = bigintToBuffer(key);
  const plaintextBuffer = Buffer.from(plaintext);
  let encrypted = Buffer.alloc(plaintextBuffer.length);

  for (let i = 0; i < plaintextBuffer.length; i++) {
    encrypted[i] = plaintextBuffer[i] ^ keyBuffer[i % keyBuffer.length];
  }

  return encrypted;
}

function xorDecrypt(key, ciphertext) {
  const keyBuffer = bigintToBuffer(key);
  let decrypted = Buffer.alloc(ciphertext.length);

  for (let i = 0; i < ciphertext.length; i++) {
    decrypted[i] = ciphertext[i] ^ keyBuffer[i % keyBuffer.length];
  }

  return decrypted;
}

const { publicKey, privateKey } = keyPair();
const keyBigInt = BigInt(`0x${privateKey}`);
const message = "Hello, World!";
const encrypted = xorEncrypt(keyBigInt, message);
const decrypted = xorDecrypt(keyBigInt, encrypted);

console.log(`Original: ${message}`);
console.log(`Encrypted: ${encrypted.toString("hex")}`);
console.log(`Decrypted: ${decrypted.toString()}`);
