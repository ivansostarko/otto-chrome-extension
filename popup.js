(function(){
  const $ = (sel)=>document.querySelector(sel);
  const status = (msg)=>{ $('#status').textContent = msg; };

  function ensureKey(){
    let k = $('#keyB64').value.trim();
    if (!k){
      const rand = crypto.getRandomValues(new Uint8Array(32));
      $('#keyB64').value = OTTO.b64(rand);
      return rand;
    }
    try {
      const bytes = OTTO.fromB64(k);
      if (bytes.length !== 32) throw new Error('key must decode to 32 bytes');
      return bytes;
    } catch(e){
      alert('Invalid Base64 key: ' + e.message);
      throw e;
    }
  }

  $('#genKey').addEventListener('click', ()=>{
    const rand = crypto.getRandomValues(new Uint8Array(32));
    $('#keyB64').value = OTTO.b64(rand);
  });

  $('#encText').addEventListener('click', async ()=>{
    try {
      const key = ensureKey();
      const pt = OTTO.encodeUTF8($('#plain').value || '');
      const {header, cat} = await OTTO.encryptString(pt, key);
      $('#headerB64').value = OTTO.b64(header);
      $('#cipherB64').value = OTTO.b64(cat);
      status('Text encrypted.');
    } catch(e){ status('Error: ' + e.message); }
  });

  $('#decText').addEventListener('click', async ()=>{
    try {
      const key = ensureKey();
      const header = OTTO.fromB64($('#headerB64').value || '');
      const cipher = OTTO.fromB64($('#cipherB64').value || '');
      const pt = await OTTO.decryptString(cipher, header, key);
      $('#decrypted').value = OTTO.decodeUTF8(pt);
      status('Text decrypted.');
    } catch(e){ status('Error: ' + e.message); }
  });

  async function downloadBlob(blob, name){
    const url = URL.createObjectURL(blob);
    await chrome.downloads.download({ url, filename: name, saveAs: true });
    setTimeout(()=>URL.revokeObjectURL(url), 30_000);
  }

  $('#encFile').addEventListener('click', async ()=>{
    const f = $('#fileIn').files[0];
    if (!f){ status('Choose a file first.'); return; }
    try {
      const key = ensureKey();
      status('Encrypting...');
      const blob = await OTTO.encryptFile(f, key, 1<<20);
      const outName = f.name + '.otto';
      await downloadBlob(blob, outName);
      status('Encrypted → ' + outName);
    } catch(e){ status('Error: ' + e.message); }
  });

  $('#decFile').addEventListener('click', async ()=>{
    const f = $('#fileIn').files[0];
    if (!f){ status('Choose a .otto file to decrypt.'); return; }
    try {
      const key = ensureKey();
      status('Decrypting...');
      const blob = await OTTO.decryptFile(f, key);
      const base = f.name.endsWith('.otto') ? f.name.slice(0,-5) : (f.name + '.dec');
      await downloadBlob(blob, base + '.dec');
      status('Decrypted → ' + base + '.dec');
    } catch(e){ status('Error: ' + e.message); }
  });
})();