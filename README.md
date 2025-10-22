# OTTO Encryptor — Chrome Extension

A Chrome extension that encrypts/decrypts **text** and **files** using the **OTTO** format (AES‑256‑GCM + HKDF, chunked streaming), fully wire‑compatible with the Laravel/PHP SDK and other OTTO SDKs.

## Features
- **Text:** encrypts to `HEADER_B64` and `CIPHER_B64 (ct||tag)`; decrypts back.
- **Files:** encrypts any file (photo/audio/video/docs) to `*.otto`; decrypts `*.otto` back to the original.
- **Key input:** Base64 32‑byte key; one‑click random generator.
- Uses WebCrypto (HKDF‑SHA256, AES‑GCM), deterministic HKDF‑SIV‑style nonces.

## Install (Developer mode)
1. Download and unzip this folder.
2. Visit `chrome://extensions` → enable **Developer mode**.
3. Click **Load unpacked** → select the unzipped folder.
4. Pin **OTTO Encryptor** to the toolbar and click the icon to open the popup.

## How it works (format)
- **Header:** `"OTTO1" | 0xA1 | 0x02 | flags | 0x00 | u16_be(16) | file_salt[16]`
- **Keys:**  
  - `encKey  = HKDF(rawKey32, salt=file_salt, info="OTTO-ENC-KEY", 32)`  
  - `nonceKey= HKDF(rawKey32, salt=file_salt, info="OTTO-NONCE-KEY", 32)`  
- **Nonces:** `HKDF(nonceKey, salt="", info="OTTO-CHUNK-NONCE" || counter_be64, 12)`
- **AEAD:** AES‑256‑GCM (tag 16B), **AAD = header**
- **Streaming container:** `header || [u32_be ct_len || ct || tag16]*`

> Note: For simplicity in the browser, file encryption is processed in chunks but buffered into a Blob before download.

## Permissions
- `downloads` — to save encrypted/decrypted files you create from the popup.

MIT © 2025 Ivan Doe
