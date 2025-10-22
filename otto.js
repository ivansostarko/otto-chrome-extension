// OTTO format (browser): AES-256-GCM, HKDF-SHA256, HKDF-SIV nonces, streaming container
// Header: 'OTTO1' | 0xA1 | 0x02 | flags | 0x00 | u16_be(16) | file_salt[16]
const OTTO = (()=>{
  const magic = new TextEncoder().encode('OTTO1');
  const ALGO_ID = 0xA1;
  const KDF_RAW = 0x02;
  const FLAG_CHUNKED = 0x01;
  const FIXED_HDR = 11;
  const FILE_SALT = 16;
  const TAG_LEN = 16;
  const NONCE_LEN = 12;

  const te = new TextEncoder();
  const td = new TextDecoder();

  function u16be(v){ return new Uint8Array([ (v>>8)&0xff, v&0xff ]); }
  function u32be(v){ return new Uint8Array([ (v>>>24)&0xff,(v>>>16)&0xff,(v>>>8)&0xff,v&0xff ]); }
  function be64(counter){
    const b = new Uint8Array(8);
    for (let i=7;i>=0;i--){ b[i]=counter&0xff; counter=Math.floor(counter/256); }
    return b;
  }
  function concat(...arrs){
    let len=0; for(const a of arrs) len+=a.length;
    const out = new Uint8Array(len); let o=0;
    for(const a of arrs){ out.set(a,o); o+=a.length; }
    return out;
  }

  async function hkdf(ikm, salt, info, outLen){
    const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({name:'HKDF', hash:'SHA-256', salt, info}, base, outLen*8);
    return new Uint8Array(bits);
  }

  async function deriveKeys(rawKey32, salt16){
    const encKey = await hkdf(rawKey32, salt16, te.encode('OTTO-ENC-KEY'), 32);
    const nonceKey = await hkdf(rawKey32, salt16, te.encode('OTTO-NONCE-KEY'), 32);
    return {encKey, nonceKey};
  }

  async function deriveChunkNonce(nonceKey, counter){
    const info = concat(te.encode('OTTO-CHUNK-NONCE'), be64(counter));
    // HKDF-SIV style: IKM=nonceKey, salt="", info as above
    return await hkdf(nonceKey, new Uint8Array([]), info, NONCE_LEN);
  }

  function buildHeader(fileSalt16, chunked){
    const flags = chunked ? FLAG_CHUNKED : 0x00;
    return concat(magic, new Uint8Array([ALGO_ID, KDF_RAW, flags, 0x00]), u16be(FILE_SALT), fileSalt16);
  }

  function parseHeader(header){
    if (header.length < FIXED_HDR) throw new Error('header too short');
    for (let i=0;i<5;i++) if (header[i]!==magic[i]) throw new Error('bad magic');
    if (header[5]!==ALGO_ID) throw new Error('algo mismatch');
    if (header[6]!==KDF_RAW) throw new Error('kdf mismatch');
    const varLen = (header[9]<<8) | header[10];
    if (header.length !== FIXED_HDR + varLen) throw new Error('header len mismatch');
    if (varLen < FILE_SALT) throw new Error('missing file salt');
    const fileSalt = header.slice(FIXED_HDR, FIXED_HDR+FILE_SALT);
    const chunked = (header[7] & FLAG_CHUNKED) !== 0;
    return {fileSalt, chunked};
  }

  async function aesGcmEncrypt(encKey, nonce, aad, pt){
    const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['encrypt']);
    const cat = await crypto.subtle.encrypt({name:'AES-GCM', iv:nonce, additionalData:aad, tagLength:128}, key, pt);
    return new Uint8Array(cat);
  }
  async function aesGcmDecrypt(encKey, nonce, aad, cat){
    const key = await crypto.subtle.importKey('raw', encKey, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:nonce, additionalData:aad, tagLength:128}, key, cat);
    return new Uint8Array(pt);
  }

  // ===== In-memory text =====
  async function encryptString(utf8Bytes, rawKey32){
    if (rawKey32.length !== 32) throw new Error('rawKey32 must be 32 bytes');
    const fileSalt = crypto.getRandomValues(new Uint8Array(FILE_SALT));
    const header = buildHeader(fileSalt, false);
    const {encKey, nonceKey} = await deriveKeys(rawKey32, fileSalt);
    const nonce = await deriveChunkNonce(nonceKey, 0n);
    const cat = await aesGcmEncrypt(encKey, nonce, header, utf8Bytes);
    return {header, cat};
  }
  async function decryptString(cat, header, rawKey32){
    if (rawKey32.length !== 32) throw new Error('rawKey32 must be 32 bytes');
    const {fileSalt} = parseHeader(header);
    const {encKey, nonceKey} = await deriveKeys(rawKey32, fileSalt);
    const nonce = await deriveChunkNonce(nonceKey, 0n);
    const pt = await aesGcmDecrypt(encKey, nonce, header, cat);
    return pt;
  }

  // ===== Files (chunked) =====
  async function encryptFile(file, rawKey32, chunkBytes=1<<20){
    if (rawKey32.length !== 32) throw new Error('rawKey32 must be 32 bytes');
    const fileSalt = crypto.getRandomValues(new Uint8Array(FILE_SALT));
    const header = buildHeader(fileSalt, true);
    const {encKey, nonceKey} = await deriveKeys(rawKey32, fileSalt);

    const parts = [header];
    const reader = file.stream().getReader();
    let counter = 0n;
    while (true){
      const {value, done} = await reader.read();
      if (done) break;
      const chunk = new Uint8Array(value);
      const nonce = await deriveChunkNonce(nonceKey, counter++);
      const cat = await aesGcmEncrypt(encKey, nonce, header, chunk);
      const ct = cat.slice(0, cat.length - TAG_LEN);
      const tag = cat.slice(cat.length - TAG_LEN);
      parts.push(u32be(ct.length), ct, tag);
    }
    return new Blob(parts, {type: 'application/octet-stream'});
  }

  async function decryptFile(file, rawKey32){
    if (rawKey32.length !== 32) throw new Error('rawKey32 must be 32 bytes');
    const buf = new Uint8Array(await file.arrayBuffer()); // buffered for simplicity
    if (buf.length < FIXED_HDR + FILE_SALT) throw new Error('truncated');
    const fixed = buf.slice(0, FIXED_HDR);
    const varLen = (fixed[9]<<8) | fixed[10];
    const header = buf.slice(0, FIXED_HDR + varLen);
    const {fileSalt} = parseHeader(header);
    const {encKey, nonceKey} = await deriveKeys(rawKey32, fileSalt);
    let off = header.length;
    const outParts = [];
    let counter = 0n;
    while (off < buf.length){
      if (off + 4 > buf.length) throw new Error('truncated length');
      const clen = (buf[off]<<24) | (buf[off+1]<<16) | (buf[off+2]<<8) | buf[off+3];
      off += 4;
      if (off + clen + TAG_LEN > buf.length) throw new Error('truncated chunk');
      const ct = buf.slice(off, off+clen); off += clen;
      const tag = buf.slice(off, off+TAG_LEN); off += TAG_LEN;
      const nonce = await deriveChunkNonce(nonceKey, counter++);
      const cat = concat(ct, tag);
      const pt = await aesGcmDecrypt(encKey, nonce, header, cat);
      outParts.push(pt);
    }
    return new Blob(outParts, {type: 'application/octet-stream'});
  }

  // Helpers
  function b64(bytes){ return btoa(String.fromCharCode(...bytes)); }
  function fromB64(s){
    const bin = atob(s.trim());
    const out = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) out[i]=bin.charCodeAt(i);
    return out;
  }
  function encodeUTF8(s){ return te.encode(s); }
  function decodeUTF8(bytes){ return td.decode(bytes); }

  return { encryptString, decryptString, encryptFile, decryptFile, b64, fromB64, encodeUTF8, decodeUTF8 };
})();

window.OTTO = OTTO;
