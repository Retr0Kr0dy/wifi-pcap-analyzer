function rotl32(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

function sha1(data) {
    let h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
    const len = data.length;
    const padLen = Math.ceil((len + 9) / 64) * 64;
    const padded = new Uint8Array(padLen);
    padded.set(data);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padLen - 4, (len * 8) >>> 0, false);
    dv.setUint32(padLen - 8, Math.floor(len / 0x20000000) >>> 0, false);
    for (let i = 0; i < padLen; i += 64) {
        const w = new Uint32Array(80);
        for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j * 4, false);
        for (let j = 16; j < 80; j++) w[j] = rotl32(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
        let a = h0, b = h1, c = h2, d = h3, e = h4;
        for (let j = 0; j < 80; j++) {
            let f, k;
            if      (j < 20) { f = ((b & c) | (~b & d)) >>> 0; k = 0x5A827999; }
            else if (j < 40) { f = (b ^ c ^ d) >>> 0;           k = 0x6ED9EBA1; }
            else if (j < 60) { f = ((b & c) | (b & d) | (c & d)) >>> 0; k = 0x8F1BBCDC; }
            else             { f = (b ^ c ^ d) >>> 0;           k = 0xCA62C1D6; }
            const t = (rotl32(a, 5) + f + e + k + w[j]) >>> 0;
            e = d; d = c; c = rotl32(b, 30); b = a; a = t;
        }
        h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0; h4=(h4+e)>>>0;
    }
    const out = new Uint8Array(20);
    const ov = new DataView(out.buffer);
    ov.setUint32(0,h0,false); ov.setUint32(4,h1,false); ov.setUint32(8,h2,false);
    ov.setUint32(12,h3,false); ov.setUint32(16,h4,false);
    return out;
}

function hmacSha1(key, data) {
    const B = 64;
    let k = key.length > B ? sha1(key) : key;
    const kpad = new Uint8Array(B); kpad.set(k);
    const ipad = new Uint8Array(B + data.length);
    const opad = new Uint8Array(B + 20);
    for (let i = 0; i < B; i++) { ipad[i] = kpad[i] ^ 0x36; opad[i] = kpad[i] ^ 0x5c; }
    ipad.set(data, B);
    opad.set(sha1(ipad), B);
    return sha1(opad);
}

function sha1Prf(key, label, data, outLen) {
    const lenc = new TextEncoder().encode(label);
    const buf  = new Uint8Array(lenc.length + 1 + data.length + 1);
    buf.set(lenc);
    buf[lenc.length] = 0x00;
    buf.set(data, lenc.length + 1);
    const chunks = [];
    let acc = 0;
    for (let i = 0; acc < outLen; i++) {
        buf[buf.length - 1] = i;
        const h = hmacSha1(key, buf);
        chunks.push(h); acc += h.length;
    }
    const all = new Uint8Array(acc);
    let off = 0; for (const c of chunks) { all.set(c, off); off += c.length; }
    return all.slice(0, outLen);
}

function concatU8(...arrs) {
    const total = arrs.reduce((s, a) => s + a.length, 0);
    const out = new Uint8Array(total); let off = 0;
    for (const a of arrs) { out.set(a, off); off += a.length; }
    return out;
}

function cmpU8(a, b) {
    for (let i = 0; i < a.length; i++) { if (a[i] < b[i]) return -1; if (a[i] > b[i]) return 1; }
    return 0;
}

function parseMac(mac) {
    return new Uint8Array(mac.split(':').map(x => parseInt(x, 16)));
}

function zeroMicField(eapolArr) {
    const z = new Uint8Array(eapolArr);
    z.fill(0, 81, 97);
    return z;
}

self.onmessage = async function(e) {
    const { ssid, bssid, sta, anonce, snonce, micFrames, wordlist, startIdx, endIdx, workerId } = e.data;

    const AN = new Uint8Array(anonce);
    const SN = new Uint8Array(snonce);
    const apMac  = parseMac(bssid);
    const staMac = parseMac(sta);
    const macMin   = cmpU8(apMac, staMac)   <= 0 ? apMac  : staMac;
    const macMax   = cmpU8(apMac, staMac)   <= 0 ? staMac : apMac;
    const nonceMin = cmpU8(AN, SN) <= 0 ? AN : SN;
    const nonceMax = cmpU8(AN, SN) <= 0 ? SN : AN;
    const ptkData  = concatU8(macMin, macMax, nonceMin, nonceMax);

    const enc   = new TextEncoder();
    const lines = wordlist.split('\\n');
    const total = lines.length;
    const t0    = Date.now();
    let triedCount = 0;

    for (let i = startIdx; i < endIdx; i++) {
        const pass = lines[i].trim();
        if (pass.length < 8 || pass.length > 63) continue;
        triedCount++;

        let pmk;
        try {
            const km = await crypto.subtle.importKey(
                'raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
            const bits = await crypto.subtle.deriveBits(
                { name:'PBKDF2', hash:'SHA-1', salt:enc.encode(ssid), iterations:4096 },
                km, 256);
            pmk = new Uint8Array(bits);
        } catch(_) { continue; }

        const ptk = sha1Prf(pmk, 'Pairwise key expansion', ptkData, 64);
        const kck = ptk.slice(0, 16);

        let found = false;
        for (const mf of micFrames) {
            const eapol  = new Uint8Array(mf.eapol);
            const capMic = mf.mic;
            const zeroed = zeroMicField(mf.eapol);
            const calcMic = hmacSha1(kck, zeroed).slice(0, 16);
            let match = true;
            for (let j = 0; j < 16; j++) { if (calcMic[j] !== capMic[j]) { match = false; break; } }
            if (match) { found = true; break; }
        }

        if (found) {
            self.postMessage({ type:'found', password:pass, tried:triedCount, total,
                               elapsed:(Date.now()-t0)/1000, workerId });
            return;
        }

        if (triedCount % 50 === 0)
            self.postMessage({ type:'progress', tried:triedCount, total:total, elapsed:(Date.now()-t0)/1000, workerId });
    }
    self.postMessage({ type:'done', tried:triedCount, total:total, elapsed:(Date.now()-t0)/1000, workerId });
};
