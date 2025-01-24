const crypto = require("crypto");
const EC = require("elliptic").ec;

// Initialize elliptic curve
const ec = new EC("secp256k1");

// Generate key pairs for Alice and Bob
const aliceKeyPair = ec.genKeyPair();
const bobKeyPair = ec.genKeyPair();

const alicePrivateKey = aliceKeyPair.getPrivate("hex");
const alicePublicKey = aliceKeyPair.getPublic("hex");

const bobPrivateKey = bobKeyPair.getPrivate("hex");
const bobPublicKey = bobKeyPair.getPublic("hex");

console.log("Alice's Public Key:", alicePublicKey);
console.log("Bob's Public Key:", bobPublicKey);

// Step 1: Generate AES key (32 bytes for AES-256)
const generateAESKey = () => {
  return crypto.randomBytes(32); // 256-bit AES key
};

// Step 2: Encrypt the AES key using Bob's public key
const encryptAESKey = (aesKey, bobPublicKey) => {
  const bobPubKey = ec.keyFromPublic(bobPublicKey, "hex");
  const sharedKey = bobPubKey.getPublic().mul(aliceKeyPair.getPrivate()); // Derive shared key
  const hashedSharedKey = crypto
    .createHash("sha256")
    .update(sharedKey.toString(16))
    .digest();

  // Encrypt AES key using the shared key
  const iv = crypto.randomBytes(16); // AES IV
  const cipher = crypto.createCipheriv("aes-256-cbc", hashedSharedKey, iv);
  let encryptedAESKey = cipher.update(aesKey, "utf8", "hex");
  encryptedAESKey += cipher.final("hex");

  return { encryptedAESKey, iv: iv.toString("hex") };
};

// Step 3: Encrypt the AES key for Alice as well
const encryptAESKeyForAlice = (aesKey, alicePublicKey) => {
  const alicePubKey = ec.keyFromPublic(alicePublicKey, "hex");
  const sharedKey = alicePubKey.getPublic().mul(bobKeyPair.getPrivate()); // Derive shared key
  const hashedSharedKey = crypto
    .createHash("sha256")
    .update(sharedKey.toString(16))
    .digest();

  // Encrypt AES key using the shared key
  const iv = crypto.randomBytes(16); // AES IV
  const cipher = crypto.createCipheriv("aes-256-cbc", hashedSharedKey, iv);
  let encryptedAESKey = cipher.update(aesKey, "utf8", "hex");
  encryptedAESKey += cipher.final("hex");

  return { encryptedAESKey, iv: iv.toString("hex") };
};

// Step 4: Decrypt the AES key using Bob's private key
const decryptAESKey = (encryptedAESKey, ivHex, bobPrivateKey) => {
  const bobPrivKey = ec.keyFromPrivate(bobPrivateKey);
  const sharedKey = bobPrivKey.getPublic().mul(aliceKeyPair.getPrivate()); // Derive shared key
  const hashedSharedKey = crypto
    .createHash("sha256")
    .update(sharedKey.toString(16))
    .digest();

  // Decrypt AES key using the shared key
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", hashedSharedKey, iv);
  let decryptedAESKey = decipher.update(encryptedAESKey, "hex", "utf8");
  decryptedAESKey += decipher.final("utf8");

  return decryptedAESKey;
};

// Step 5: Decrypt the AES key using Alice's private key
const decryptAESKeyForAlice = (encryptedAESKey, ivHex, alicePrivateKey) => {
  const alicePrivKey = ec.keyFromPrivate(alicePrivateKey);
  const sharedKey = alicePrivKey.getPublic().mul(bobKeyPair.getPrivate()); // Derive shared key
  const hashedSharedKey = crypto
    .createHash("sha256")
    .update(sharedKey.toString(16))
    .digest();

  // Decrypt AES key using the shared key
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", hashedSharedKey, iv);
  let decryptedAESKey = decipher.update(encryptedAESKey, "hex", "utf8");
  decryptedAESKey += decipher.final("utf8");

  return decryptedAESKey;
};

// Step 6: Encrypt a message using the AES key
const encryptMessage = (message, aesKey) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  let encryptedMessage = cipher.update(message, "utf8", "hex");
  encryptedMessage += cipher.final("hex");

  return { encryptedMessage, iv: iv.toString("hex") };
};

// Step 7: Decrypt the message using the AES key
const decryptMessage = (encryptedMessage, aesKey, ivHex) => {
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
  let decryptedMessage = decipher.update(encryptedMessage, "hex", "utf8");
  decryptedMessage += decipher.final("utf8");

  return decryptedMessage;
};

// Main logic
(async () => {
  // Alice generates an AES key
  const aesKey = generateAESKey();
  console.log("Generated AES Key (hex):", aesKey.toString("hex"));

  // Encrypt the AES key for Bob
  const { encryptedAESKey: encryptedForBob, iv: ivForBob } = encryptAESKey(
    aesKey.toString("hex"),
    bobPublicKey
  );
  console.log("Encrypted AES Key for Bob:", encryptedForBob);
  console.log("IV for Bob's AES Key:", ivForBob);

  // Encrypt the AES key for Alice
  const { encryptedAESKey: encryptedForAlice, iv: ivForAlice } =
    encryptAESKeyForAlice(aesKey.toString("hex"), alicePublicKey);
  console.log("Encrypted AES Key for Alice:", encryptedForAlice);
  console.log("IV for Alice's AES Key:", ivForAlice);

  // Bob decrypts the AES key with his private key
  const decryptedAESKeyHexForBob = decryptAESKey(
    encryptedForBob,
    ivForBob,
    bobPrivateKey
  );
  const decryptedAESKeyForBob = Buffer.from(decryptedAESKeyHexForBob, "hex");
  console.log("Decrypted AES Key for Bob (hex):", decryptedAESKeyHexForBob);

  // Alice decrypts the AES key with her private key
  const decryptedAESKeyHexForAlice = decryptAESKeyForAlice(
    encryptedForAlice,
    ivForAlice,
    alicePrivateKey
  );
  const decryptedAESKeyForAlice = Buffer.from(
    decryptedAESKeyHexForAlice,
    "hex"
  );
  console.log("Decrypted AES Key for Alice (hex):", decryptedAESKeyHexForAlice);

  // Encrypt a message using the AES key (from Alice)
  const message = "This is a secret message!";
  const { encryptedMessage, iv: messageIV } = encryptMessage(message, aesKey);
  console.log("Encrypted Message:", encryptedMessage);
  console.log("IV for Message:", messageIV);

  // Bob decrypts the message using the decrypted AES key
  const decryptedMessageForBob = decryptMessage(
    encryptedMessage,
    decryptedAESKeyForBob,
    messageIV
  );
  console.log("Decrypted Message for Bob:", decryptedMessageForBob);

  // Alice decrypts the message using the decrypted AES key
  const decryptedMessageForAlice = decryptMessage(
    encryptedMessage,
    decryptedAESKeyForAlice,
    messageIV
  );
  console.log("Decrypted Message for Alice:", decryptedMessageForAlice);
})();
