// Utility: convert Uint8Array -> CryptoJS WordArray
function uint8ArrayToWordArray(u8) {
  var words = [];
  for (var i = 0; i < u8.length; i += 4) {
    words.push(
      ((u8[i] || 0) << 24) |
      ((u8[i + 1] || 0) << 16) |
      ((u8[i + 2] || 0) << 8) |
      ((u8[i + 3] || 0))
    );
  }
  return CryptoJS.lib.WordArray.create(words, u8.length);
}

// Utility: convert CryptoJS WordArray -> Uint8Array
function wordArrayToUint8Array(wordArray) {
  var words = wordArray.words;
  var sigBytes = wordArray.sigBytes;
  var u8 = new Uint8Array(sigBytes);
  var i = 0, j = 0;
  while (i < sigBytes) {
    var w = words[j++];
    u8[i++] = (w >> 24) & 0xff;
    if (i === sigBytes) break;
    u8[i++] = (w >> 16) & 0xff;
    if (i === sigBytes) break;
    u8[i++] = (w >> 8) & 0xff;
    if (i === sigBytes) break;
    u8[i++] = w & 0xff;
  }
  return u8;
}

function randomBytes(n) {
  var b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function deriveKey(password, saltWordArray, keySizeBits) {
  // Derive a key twice as long as needed: half for encryption, half for HMAC
  // HMAC key will be fixed at 256 bits (32 bytes) for HMAC-SHA256
  const totalKeySizeWords = (keySizeBits / 32) + (256 / 32);
  const derivedKey = CryptoJS.PBKDF2(password, saltWordArray, {
    keySize: totalKeySizeWords,
    iterations: 10000,
    hasher: CryptoJS.algo.SHA256
  });

  const encKey = CryptoJS.lib.WordArray.create(derivedKey.words.slice(0, keySizeBits / 32), keySizeBits / 8);
  const hmacKey = CryptoJS.lib.WordArray.create(derivedKey.words.slice(keySizeBits / 32), 256 / 8);
  return { encKey, hmacKey };
}

// Map UI choices to cipher and sizes
function getCipherAndSizes(algo, keySizeStr) {
  var keyBits = parseInt(keySizeStr, 10);
  if (algo === 'aes') {
    return { cipher: CryptoJS.AES, keyBits: keyBits, ivBytes: 16 };
  }
  // DES options: 64 -> DES, 192 -> TripleDES (CryptoJS uses 192-bit key for 3DES)
  if (algo === 'des') {
    if (keyBits === 64) return { cipher: CryptoJS.DES, keyBits: 64, ivBytes: 8 };
    return { cipher: CryptoJS.TripleDES, keyBits: 192, ivBytes: 8 };
  }
  throw new Error('Unsupported algorithm');
}

// --- Header Logic ---
const MAGIC = 0x4645; // "FE" for File Encryptor

// Maps string identifiers to a 1-byte code for the header
const ALGO_MAP = { aes: 1, des: 2, tripledes: 3 };
const KEY_SIZE_MAP = { 64: 1, 128: 2, 192: 3, 256: 4 };

// Reverse maps for decryption
const ALGO_MAP_REV = { 1: 'aes', 2: 'des', 3: 'tripledes' };
const KEY_SIZE_MAP_REV = { 1: 64, 2: 128, 3: 192, 4: 256 };

function createHeader(algo, keyBits) {
  const header = new Uint8Array(4);
  const view = new DataView(header.buffer);

  let algoId = algo === 'aes' ? ALGO_MAP.aes : (keyBits === 192 ? ALGO_MAP.tripledes : ALGO_MAP.des);
  let keySizeId = KEY_SIZE_MAP[keyBits];

  view.setUint16(0, MAGIC, false); // Magic bytes (big-endian)
  view.setUint8(2, algoId);
  view.setUint8(3, keySizeId);

  return header;
}

function parseHeader(fileBytes) {
  if (fileBytes.length < 4) throw new Error('Invalid file: too short to contain a header.');
  const view = new DataView(fileBytes.buffer.slice(0, 4));

  if (view.getUint16(0, false) !== MAGIC) {
    throw new Error('Not a valid encrypted file (magic number mismatch).');
  }

  const algoId = view.getUint8(2);
  const keySizeId = view.getUint8(3);

  const algo = ALGO_MAP_REV[algoId] === 'tripledes' ? 'des' : ALGO_MAP_REV[algoId];
  const keyBits = KEY_SIZE_MAP_REV[keySizeId];
  return { algo, keyBits, headerSize: 4 };
}

async function readFileArrayBuffer(file) {
  return await file.arrayBuffer();
}

document.getElementById('cryptoForm').addEventListener('submit', async function (e) {
  e.preventDefault();

  const fileInput = document.getElementById('fileInput');
  const password = document.getElementById('password').value;
  const mode = document.querySelector('input[name="mode"]:checked').value; // encrypt|decrypt
  const algo = document.querySelector('input[name="algo"]:checked').value; // aes|des
  const keySize = document.getElementById('keySize').value;

  const statusDiv = document.getElementById('status');
  const resultDiv = document.getElementById('result');
  const downloadLink = document.getElementById('downloadLink');
  statusDiv.textContent = '';
  resultDiv.style.display = 'none';

  if (!fileInput.files[0]) { statusDiv.textContent = 'Select a file'; return; }
  if (!password) { statusDiv.textContent = 'Enter a password'; return; }

  try {
    const file = fileInput.files[0];
    const { cipher, keyBits, ivBytes } = getCipherAndSizes(algo, keySize);

    const arrayBuffer = await readFileArrayBuffer(file);
    const fileBytes = new Uint8Array(arrayBuffer);

    if (mode === 'encrypt') {
      // Create header
      const header = createHeader(algo, keyBits);

      // Generate salt + iv
      const salt = randomBytes(16);
      const iv = randomBytes(ivBytes);

      const saltWA = uint8ArrayToWordArray(salt);
      const ivWA = uint8ArrayToWordArray(iv);
      const { encKey, hmacKey } = deriveKey(password, saltWA, keyBits);

      const dataWA = uint8ArrayToWordArray(fileBytes);

      // Compute HMAC on the plaintext, then encrypt plaintext + HMAC
      const hmac = CryptoJS.HmacSHA256(dataWA, hmacKey);
      const hmacBytes = wordArrayToUint8Array(hmac);
      const dataWithHmac = new Uint8Array(fileBytes.length + hmacBytes.length);
      dataWithHmac.set(fileBytes, 0);
      dataWithHmac.set(hmacBytes, fileBytes.length);
      const dataWithHmacWA = uint8ArrayToWordArray(dataWithHmac);

      const encrypted = cipher.encrypt(dataWithHmacWA, encKey, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const cipherBytes = wordArrayToUint8Array(encrypted.ciphertext);

      const out = new Uint8Array(header.byteLength + salt.byteLength + iv.byteLength + cipherBytes.byteLength);
      out.set(header, 0);
      out.set(salt, header.byteLength);
      out.set(iv, header.byteLength + salt.byteLength);
      out.set(cipherBytes, header.byteLength + salt.byteLength + iv.byteLength);

      const blob = new Blob([out], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const ext = algo === 'aes' ? '.aes' : (keyBits === 64 ? '.des' : '.3des');
      downloadLink.href = url;
      downloadLink.download = file.name + ext;
      downloadLink.textContent = 'Download encrypted file';
      resultDiv.style.display = 'block';
      statusDiv.textContent = 'Encryption complete';
    } else {
      // Decrypt: First, parse header to get parameters
      const { algo: fileAlgo, keyBits: fileKeyBits, headerSize } = parseHeader(fileBytes);
      const { cipher, keyBits, ivBytes } = getCipherAndSizes(fileAlgo, fileKeyBits.toString());

      // Update UI to reflect detected settings
      updateUiForDecryption(fileAlgo, fileKeyBits);

      const hmacSize = 32; // HMAC-SHA256 produces a 32-byte tag
      if (fileBytes.length < headerSize + 16 + ivBytes) throw new Error('File too small or not a valid encrypted file');

      const salt = fileBytes.slice(headerSize, headerSize + 16);
      const iv = fileBytes.slice(headerSize + 16, headerSize + 16 + ivBytes);
      const ciphertext = fileBytes.slice(headerSize + 16 + ivBytes);

      const saltWA = uint8ArrayToWordArray(salt);
      const ivWA = uint8ArrayToWordArray(iv);
      const cipherWA = uint8ArrayToWordArray(ciphertext);

      const { encKey, hmacKey } = deriveKey(password, saltWA, keyBits);
      
      // Decrypt first, then verify HMAC
      const decrypted = cipher.decrypt({ ciphertext: cipherWA }, encKey, { iv: ivWA, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 });
      const decryptedBytes = wordArrayToUint8Array(decrypted);

      if (decryptedBytes.length < hmacSize) throw new Error('Decryption failed: invalid data size.');
      const plainBytes = decryptedBytes.slice(0, decryptedBytes.length - hmacSize);
      const storedHmacBytes = decryptedBytes.slice(decryptedBytes.length - hmacSize);
      const computedHmac = CryptoJS.HmacSHA256(uint8ArrayToWordArray(plainBytes), hmacKey);
      if (computedHmac.toString() !== uint8ArrayToWordArray(storedHmacBytes).toString()) {
        throw new Error('Decryption failed: file has been tampered with or wrong password.');
      }

      const blob = new Blob([plainBytes], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      // strip common extension
      const originalName = file.name.replace(/(\.aes|\.des|\.3des)$/i, '');
      downloadLink.href = url;
      downloadLink.download = originalName || (file.name + '.dec');
      downloadLink.textContent = 'Download decrypted file';
      resultDiv.style.display = 'block';
      statusDiv.textContent = 'Decryption complete';
    }
  } catch (err) {
    console.error(err);
    statusDiv.textContent = 'Error: ' + (err.message || err);
  }
});

function updateUiForDecryption(algo, keyBits) {
  document.querySelector(`input[name="algo"][value="${algo}"]`).checked = true;
  updateKeySizeOptions();
  document.getElementById('keySize').value = keyBits;
}

const algoRadios = document.querySelectorAll('input[name="algo"]');
const keySizeSelect = document.getElementById('keySize');

function updateKeySizeOptions() {
    const selectedAlgo = document.querySelector('input[name="algo"]:checked').value;
    if (selectedAlgo === 'aes') {
        keySizeSelect.innerHTML = '<option value="128">AES - 128 bits</option><option value="192">AES - 192 bits</option><option value="256" selected>AES - 256 bits</option>';
    } else {
        keySizeSelect.innerHTML = '<option value="64">DES - 64 bits (DES)</option><option value="192" selected>3DES - 192 bits (Triple DES)</option>';
    }
}

algoRadios.forEach(r => r.addEventListener('change', updateKeySizeOptions));

// Initial population
updateKeySizeOptions();
