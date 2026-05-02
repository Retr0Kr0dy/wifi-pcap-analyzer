'use strict';

// ════════════════════════════════════════════════════════════════
// QUIET STATUS HELPER
// ════════════════════════════════════════════════════════════════
const logPanel = null;
function addLog(msg, type='info') {
    if (type === 'error') console.error(msg);
}

// ════════════════════════════════════════════════════════════════
// PCAP PARSER
// ════════════════════════════════════════════════════════════════
function parsePcap(buf) {
    const dv = new DataView(buf);
    const magic = dv.getUint32(0, true);
    if (magic === 0x0A0D0D0A)
        throw new Error('PCAPNG not supported — convert first:\n  tshark -F pcap -r file.pcapng -w file.pcap');
    if (magic !== 0xa1b2c3d4 && magic !== 0xd4c3b2a1)
        throw new Error(`Unknown file magic 0x${magic.toString(16)} — is this a PCAP file?`);
    const le = (magic === 0xa1b2c3d4);
    const linkType = dv.getUint32(20, le);
    const pkts = [];
    let off = 24;
    while (off + 16 <= buf.byteLength) {
        const inclLen = dv.getUint32(off + 8, le);
        off += 16;
        if (off + inclLen > buf.byteLength) break;
        pkts.push({ data: new Uint8Array(buf, off, inclLen), linkType });
        off += inclLen;
    }
    return pkts;
}

// ════════════════════════════════════════════════════════════════
// 802.11 HELPERS
// ════════════════════════════════════════════════════════════════
function strip80211(pkt) {
    if (pkt.linkType === 127) {
        if (pkt.data.length < 4) return null;
        const rtLen = pkt.data[2] | (pkt.data[3] << 8);
        if (rtLen > pkt.data.length) return null;
        return pkt.data.slice(rtLen);
    }
    if (pkt.linkType === 105) return pkt.data;
    return null;
}

function macStr(buf, off) {
    return Array.from(buf.subarray(off, off + 6), b => b.toString(16).padStart(2, '0')).join(':');
}

// ════════════════════════════════════════════════════════════════
// RSN / WPA IE PARSERS
// ════════════════════════════════════════════════════════════════
const RSN_CIPHER_NAMES = {0:'group',1:'WEP-40',2:'TKIP',4:'CCMP-128',5:'WEP-104',
                           8:'GCMP-128',9:'GCMP-256',10:'CCMP-256'};
const RSN_AKM_NAMES    = {1:'802.1X',2:'PSK',3:'FT-802.1X',4:'FT-PSK',
                           5:'802.1X-SHA256',6:'PSK-SHA256',8:'SAE',9:'FT-SAE',18:'OWE'};

function suiteName(b4, isAkm) {
    const oui = (b4[0] << 16) | (b4[1] << 8) | b4[2];
    const t   = b4[3];
    if (oui === 0x000fac) return (isAkm ? RSN_AKM_NAMES : RSN_CIPHER_NAMES)[t] || `AC:${t}`;
    if (oui === 0x0050f2) {
        if (isAkm) return t === 1 ? '802.1X' : t === 2 ? 'PSK' : `WPA:${t}`;
        return t === 2 ? 'TKIP' : t === 4 ? 'CCMP-128' : `WPA:${t}`;
    }
    return `${oui.toString(16).toUpperCase()}:${t}`;
}

function parseRsnIe(b) {
    if (b.length < 2) return null;
    let off = 2;
    const r = { kind:'RSN', group:'', pairwise:[], akms:[] };
    if (b.length >= off + 4) { r.group = suiteName(b.subarray(off, off+4), false); off += 4; }
    if (b.length >= off + 2) {
        const n = b[off] | (b[off+1] << 8); off += 2;
        for (let i = 0; i < n && off + 4 <= b.length; i++, off += 4)
            r.pairwise.push(suiteName(b.subarray(off, off+4), false));
    }
    if (b.length >= off + 2) {
        const n = b[off] | (b[off+1] << 8); off += 2;
        for (let i = 0; i < n && off + 4 <= b.length; i++, off += 4)
            r.akms.push(suiteName(b.subarray(off, off+4), true));
    }
    return r;
}

function parseWpaIe(b) {
    if (b.length < 6) return null;
    let off = 6;
    const r = { kind:'WPA', group:'', pairwise:[], akms:[] };
    if (b.length >= off + 4) { r.group = suiteName(b.subarray(off, off+4), false); off += 4; }
    if (b.length >= off + 2) {
        const n = b[off] | (b[off+1] << 8); off += 2;
        for (let i = 0; i < n && off + 4 <= b.length; i++, off += 4)
            r.pairwise.push(suiteName(b.subarray(off, off+4), false));
    }
    if (b.length >= off + 2) {
        const n = b[off] | (b[off+1] << 8); off += 2;
        for (let i = 0; i < n && off + 4 <= b.length; i++, off += 4)
            r.akms.push(suiteName(b.subarray(off, off+4), true));
    }
    return r;
}

function parseIEs(buf, off) {
    const r = { ssid: null, rsn: null, wpa: null };
    while (off + 2 <= buf.length) {
        const eid = buf[off], len = buf[off + 1];
        off += 2;
        if (off + len > buf.length) break;
        const info = buf.subarray(off, off + len);
        if (eid === 0 && r.ssid === null) {
            r.ssid = len === 0 ? '<hidden>' : new TextDecoder('utf-8', {fatal:false}).decode(info) || '<hidden>';
        } else if (eid === 48) {
            r.rsn = parseRsnIe(info);
        } else if (eid === 221 && len >= 4 &&
            info[0] === 0x00 && info[1] === 0x50 && info[2] === 0xf2 && info[3] === 0x01) {
            r.wpa = parseWpaIe(info);
        }
        off += len;
    }
    return r;
}

// ════════════════════════════════════════════════════════════════
// EAPOL EXTRACTION + KEY PARSING
// ════════════════════════════════════════════════════════════════
const EAPOL_SNAP = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

function findEapol(frame, startOff) {
    const end = frame.length - 8;
    outer: for (let i = startOff; i <= end; i++) {
        for (let j = 0; j < 8; j++) if (frame[i + j] !== EAPOL_SNAP[j]) continue outer;
        return frame.subarray(i + 8);
    }
    return null;
}

function parseEapolKey(eapol) {
    if (!eapol || eapol.length < 99) return null;
    if (eapol[1] !== 3) return null;
    const keyInfo = (eapol[5] << 8) | eapol[6];
    const descVer = keyInfo & 0x07;
    const ack     = !!(keyInfo & 0x0080);
    const micFlag = !!(keyInfo & 0x0100);
    const secure  = !!(keyInfo & 0x0200);
    const nonce   = eapol.slice(17, 49);
    const mic     = eapol.slice(81, 97);
    let msg;
    if      ( ack && !micFlag)           msg = 'M1';
    else if (!ack &&  micFlag && !secure) msg = 'M2';
    else if ( ack &&  micFlag)           msg = 'M3';
    else if (!ack &&  micFlag &&  secure) msg = 'M4';
    else                                  msg = '?';
    return { msg, descVer, nonce, mic, micFlag, ack, secure,
             eapol: Array.from(eapol) };
}

function isZero(arr) { for (const b of arr) if (b !== 0) return false; return true; }

// ════════════════════════════════════════════════════════════════
// 802.11 FRAME PROCESSOR
// ════════════════════════════════════════════════════════════════
function processFrame(frame, nets, sessions) {
    if (frame.length < 4) return;
    const fc0     = frame[0], fc1 = frame[1];
    const type    = (fc0 >> 2) & 0x3;
    const subtype = (fc0 >> 4) & 0xF;
    const toDS    = fc1 & 0x01;
    const fromDS  = (fc1 >> 1) & 0x01;
    const prot    = (fc1 >> 6) & 0x01;

    if (type === 0) {
        if (frame.length < 24) return;
        const addr1 = macStr(frame, 4);
        const addr2 = macStr(frame, 10);
        const addr3 = macStr(frame, 16);
        let bssid, ieOff;

        if (subtype === 8 || subtype === 5) {
            bssid = addr3;
            ieOff = 36;
        } else if (subtype === 0) {
            bssid = addr1;
            ieOff = 28;
        } else if (subtype === 2) {
            bssid = addr1;
            ieOff = 34;
        } else return;

        if (ieOff > frame.length) return;
        const ies = parseIEs(frame, ieOff);
        if (!nets[bssid]) nets[bssid] = { bssid, ssid: null, rsn: null, wpa: null };
        const net = nets[bssid];
        if (ies.ssid && ies.ssid !== '<hidden>') net.ssid = ies.ssid;
        if (ies.rsn && !net.rsn) net.rsn = ies.rsn;
        if (ies.wpa && !net.wpa) net.wpa = ies.wpa;

    } else if (type === 2) {
        if (prot || frame.length < 24) return;
        let hdrLen = 24;
        if (toDS && fromDS) hdrLen += 6;
        if (subtype & 0x8)  hdrLen += 2;
        if (hdrLen > frame.length) return;

        const raw = findEapol(frame, hdrLen);
        if (!raw) return;
        const parsed = parseEapolKey(raw);
        if (!parsed) return;

        let bssid, sta;
        const a1 = macStr(frame, 4), a2 = macStr(frame, 10), a3 = macStr(frame, 16);
        if      ( toDS && !fromDS) { bssid = a1; sta = a2; }
        else if (!toDS &&  fromDS) { bssid = a2; sta = a1; }
        else                        { bssid = a3; sta = a2; }

        const key = `${bssid}|${sta}`;
        if (!sessions[key]) sessions[key] = { bssid, sta, frames: [] };
        sessions[key].frames.push(parsed);
    }
}

// ════════════════════════════════════════════════════════════════
// SESSION ANALYSIS
// ════════════════════════════════════════════════════════════════
function analyzeSession(sess) {
    let anonce = null, snonce = null, micFrames = [];
    for (const f of sess.frames) {
        if ((f.msg === 'M1' || f.msg === 'M3') && !isZero(f.nonce)) anonce = f.nonce;
        if (f.msg === 'M2' && !isZero(f.nonce)) snonce = f.nonce;
        if (f.micFlag) micFrames.push(f);
    }
    return {
        msgs:      sess.frames.map(f => f.msg),
        anonce, snonce, micFrames,
        crackable: !!(anonce && snonce && micFrames.length),
    };
}

// ════════════════════════════════════════════════════════════════
// MAIN PARSE ENTRY
// ════════════════════════════════════════════════════════════════
function analyzePcap(buf) {
    const pkts = parsePcap(buf);
    const nets = {}, sessions = {};
    let dot11 = 0;
    for (const pkt of pkts) {
        const frame = strip80211(pkt);
        if (frame) { dot11++; processFrame(frame, nets, sessions); }
    }
    return { nets, sessions, pktCount: pkts.length, dot11Count: dot11 };
}

// ════════════════════════════════════════════════════════════════
// CRYPTO FUNCTIONS (MAIN SCOPE - USED BY ALL MODES)
// ════════════════════════════════════════════════════════════════
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

function formatEta(sec) {
    if (!Number.isFinite(sec) || sec < 0) return 'ETA —';
    sec = Math.ceil(sec);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h > 0) return `ETA ${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
    if (m > 0) return `ETA ${m}m ${String(s).padStart(2, '0')}s`;
    return `ETA ${s}s`;
}

function setProgress(tried, total, startTime, suffix='') {
    const elapsed = (Date.now() - startTime) / 1000;
    const rate = elapsed > 0 ? Math.round(tried / elapsed) : 0;
    const pctNum = total > 0 ? Math.min(100, (tried / total * 100)) : 0;
    const eta = rate > 0 ? ((total - tried) / rate) : NaN;
    document.getElementById('pbar').style.width = pctNum.toFixed(2) + '%';
    document.getElementById('pbar-text').textContent =
        `${tried.toLocaleString()} / ${total.toLocaleString()}  (${pctNum.toFixed(2)}%)  —  ${rate.toLocaleString()} pwd/s  —  ${formatEta(eta)}${suffix}`;
}


// Password verification function (used by all modes)
async function checkPassword(pass, payload) {
    if (pass.length < 8 || pass.length > 63) return { found: false };
    
    const enc = new TextEncoder();
    
    // PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)
    let pmk;
    try {
        const km = await crypto.subtle.importKey(
            'raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits(
            { name:'PBKDF2', hash:'SHA-1', salt:enc.encode(payload.ssid), iterations:4096 },
            km, 256);
        pmk = new Uint8Array(bits);
    } catch(_) { return { found: false }; }
    
    // PTK = SHA1-PRF(PMK, "Pairwise key expansion", macData || nonceData, 64)
    const AN = new Uint8Array(payload.anonce);
    const SN = new Uint8Array(payload.snonce);
    const apMac  = parseMac(payload.bssid);
    const staMac = parseMac(payload.sta);
    
    const macMin   = cmpU8(apMac, staMac) <= 0 ? apMac  : staMac;
    const macMax   = cmpU8(apMac, staMac) <= 0 ? staMac : apMac;
    const nonceMin = cmpU8(AN, SN) <= 0 ? AN : SN;
    const nonceMax = cmpU8(AN, SN) <= 0 ? SN : AN;
    const ptkData  = concatU8(macMin, macMax, nonceMin, nonceMax);
    
    const ptk = sha1Prf(pmk, 'Pairwise key expansion', ptkData, 64);
    const kck = ptk.slice(0, 16);
    
    let found = false;
    for (const mf of payload.micFrames) {
        const eapol  = new Uint8Array(mf.eapol);
        const capMic = mf.mic;
        const zeroed = zeroMicField(eapol);
        const calcMic = hmacSha1(kck, zeroed).slice(0, 16);
        let match = true;
        for (let j = 0; j < 16; j++) { if (calcMic[j] !== capMic[j]) { match = false; break; } }
        if (match) { found = true; break; }
    }
    
    return { found };
}

// ════════════════════════════════════════════════════════════════
// MODE 1: SINGLE WORKER SOURCE (includes crypto functions)
// ════════════════════════════════════════════════════════════════
const WORKER_SRC = __INLINE_WORKER_SINGLE__;

// ════════════════════════════════════════════════════════════════
// MODE 1: JS MULTI-WORKER SOURCE
// ════════════════════════════════════════════════════════════════
const WORKER_POOL_SRC = __INLINE_WORKER_POOL__;

// ════════════════════════════════════════════════════════════════
// MODE 3: WEBGL2 SHADER SOURCE
// ════════════════════════════════════════════════════════════════
const WEBGL2_SHADERS = {
    vertex: `
        attribute vec2 position;
        void main() {
            gl_Position = vec4(position, 0.0, 1.0);
        }
    `,
    fragment: `
        precision highp float;
        uniform float uWordCount;
        uniform float uPassIndex;
        varying vec2 vUv;
        
        void main() {
            if (vUv.x >= 1.0) {
                gl_FragColor = vec4(0.0);
                return;
            }
            gl_FragColor = vec4(1.0, 1.0, 1.0, 1.0);
        }
    `
};

// ════════════════════════════════════════════════════════════════
// APP STATE
// ════════════════════════════════════════════════════════════════
let G = { nets:{}, sessions:{}, pktCount:0, dot11Count:0 };
let currentTarget = null;
let wordlistText   = null;
let crackWorkers   = [];
let crackSettings  = { mode:'js-worker', threads:1 };
let webglContext   = null;
let crackStartTime = null;
let singleWorker   = null;
let engineCaps     = null;
let crackRunId     = 0;
let crackActive    = false;

// ════════════════════════════════════════════════════════════════
// UI HELPERS
// ════════════════════════════════════════════════════════════════
function esc(s) {
    return String(s)
        .replace(/&/g,'&amp;').replace(/</g,'&lt;')
        .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setStatus(msg, right) {
    document.getElementById('status-msg').textContent = msg;
    if (right !== undefined) document.getElementById('status-right').textContent = right;
}

function showPanel(id) {
    ['panel-load','panel-aps','panel-crack'].forEach(p =>
        document.getElementById(p).classList.toggle('active', p === id));
}

function resetToLoad() { 
    showPanel('panel-load'); 
    setStatus('Ready — drop a PCAP file', '');
    addLog('Ready to start. Drop a new PCAP file.');
}
function showAPs()     { showPanel('panel-aps'); }

// ════════════════════════════════════════════════════════════════
// RENDER AP TABLE
// ════════════════════════════════════════════════════════════════
function renderAPTable() {
    const apMap = {};
    for (const [bssid, net] of Object.entries(G.nets))
        apMap[bssid] = { bssid, ssid:net.ssid, rsn:net.rsn, wpa:net.wpa, sessions:[] };

    for (const [, sess] of Object.entries(G.sessions)) {
        if (!apMap[sess.bssid]) {
            const net = G.nets[sess.bssid] || {};
            apMap[sess.bssid] = { bssid:sess.bssid, ssid:net.ssid||null, rsn:net.rsn||null, wpa:net.wpa||null, sessions:[] };
        }
        const analysis = analyzeSession(sess);
        apMap[sess.bssid].sessions.push({ bssid:sess.bssid, sta:sess.sta, frames:sess.frames, analysis });
    }

    const aps = Object.values(apMap).sort((a,b) => (a.ssid||'\xff').localeCompare(b.ssid||'\xff'));

    document.getElementById('ap-stats').textContent =
        `${aps.length} AP${aps.length!==1?'s':''} · ${Object.keys(G.sessions).length} EAPOL session${Object.keys(G.sessions).length!==1?'s':''}`;

    const tbody = document.getElementById('ap-tbody');
    tbody.innerHTML = '';

    if (aps.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--dim);padding:30px;">No 802.11 frames found — check link type</td></tr>';
        return;
    }

    for (const ap of aps) {
        const ie = ap.rsn || ap.wpa;
        const akms = ie?.akms || [];
        const isSAE     = akms.some(a => a === 'SAE' || a.includes('WPA3'));
        const isPSK     = akms.some(a => a === 'PSK' || a === 'PSK-SHA256');
        const is8021x   = akms.some(a => a.includes('802.1X'));
        const isWpa2    = !!ap.rsn;
        const isWpa1    = !ap.rsn && !!ap.wpa;

        let badgeClass, badgeLabel;
        if      (isSAE)   { badgeClass='b-wpa3'; badgeLabel='WPA3-SAE'; }
        else if (isPSK && isWpa2) { badgeClass='b-wpa2'; badgeLabel='WPA2-PSK'; }
        else if (isPSK && isWpa1) { badgeClass='b-wpa2'; badgeLabel='WPA-PSK'; }
        else if (is8021x) { badgeClass='b-wpa3'; badgeLabel='WPA2-EAP'; }
        else if (ie)      { badgeClass='b-wpa2'; badgeLabel='WPA2'; }
        else              { badgeClass='b-open';  badgeLabel='Open/Unk'; }

        const cipher = ie
            ? [...(ie.pairwise.length ? ie.pairwise : [ie.group])].join(' / ')
            : '—';
        const akm = ie ? akms.join(', ') || '—' : '—';

        const crackableSess = ap.sessions.filter(s => s.analysis.crackable);
        let hsHtml = '';
        if (ap.sessions.length === 0) {
            hsHtml = '<span class="dim" style="font-size:10px;">no EAPOL</span>';
        } else {
            const allMsgs = [...new Set(ap.sessions.flatMap(s => s.analysis.msgs))];
            for (const m of ['M1','M2','M3','M4','?']) {
                if (allMsgs.includes(m)) hsHtml += `<span class="mbit">${m}</span>`;
            }
            hsHtml += crackableSess.length
                ? ' <span class="b-ok badge" style="margin-left:4px;">crackable</span>'
                : ' <span class="b-no badge" style="margin-left:4px;">incomplete</span>';
        }

        let actionHtml;
        if (isSAE) {
            actionHtml = '<span class="dim" style="font-size:10px;">SAE — not crackable</span>';
        } else if (is8021x) {
            actionHtml = '<span class="dim" style="font-size:10px;">EAP — not supported</span>';
        } else if (isPSK && crackableSess.length > 0) {
            actionHtml = `<button class="btn" onclick="selectTarget('${esc(ap.bssid)}')">Target →</button>`;
        } else if (isPSK) {
            actionHtml = '<span class="dim" style="font-size:10px;">PSK — incomplete hs</span>';
        } else {
            actionHtml = '<span class="dim" style="font-size:10px;">—</span>';
        }

        const ssidHtml = ap.ssid
            ? `<strong>${esc(ap.ssid)}</strong>`
            : '<span class="dim">&lt;hidden&gt;</span>';

        tbody.innerHTML += `<tr>
            <td>${ssidHtml}</td>
            <td class="mono" style="font-size:11px;color:var(--dim)">${esc(ap.bssid)}</td>
            <td><span class="badge ${badgeClass}">${badgeLabel}</span></td>
            <td style="font-size:11px;">${esc(cipher)}</td>
            <td style="font-size:11px;">${esc(akm)}</td>
            <td style="font-size:11px;text-align:center;">${ap.sessions.length}</td>
            <td>${hsHtml}</td>
            <td>${actionHtml}</td>
        </tr>`;
    }
}

// ════════════════════════════════════════════════════════════════
// SELECT TARGET + RENDER CRACK PANEL
// ════════════════════════════════════════════════════════════════
function selectTarget(bssid) {
    const net    = G.nets[bssid] || { bssid, ssid:null, rsn:null, wpa:null };
    const sesses = Object.values(G.sessions)
        .filter(s => s.bssid === bssid)
        .map(s => ({ ...s, analysis: analyzeSession(s) }));
    currentTarget = { bssid, net, sessions: sesses };

    document.getElementById('crack-target-title').textContent =
        net.ssid ? `"${net.ssid}" — ${bssid}` : bssid;

    const ie = net.rsn || net.wpa;
    document.getElementById('tgt-info').innerHTML = `
        <div class="irow"><span class="ilabel">SSID</span>
            <span class="ival">${net.ssid ? esc(net.ssid) : '<span class="dim">unknown — SSID required for crack</span>'}</span></div>
        <div class="irow"><span class="ilabel">BSSID</span>
            <span class="ival mono">${esc(bssid)}</span></div>
        <div class="irow"><span class="ilabel">Security</span>
            <span class="ival">${ie ? ie.kind : '?'}</span></div>
        <div class="irow"><span class="ilabel">Cipher</span>
            <span class="ival">${ie ? [...(ie.pairwise.length ? ie.pairwise : [ie.group])].join(', ') : '?'}</span></div>
        <div class="irow"><span class="ilabel">AKM</span>
            <span class="ival">${ie ? (ie.akms.join(', ') || '?') : '?'}</span></div>
        <div class="irow"><span class="ilabel">Sessions</span>
            <span class="ival">${sesses.length}</span></div>
    `;

    let sessHtml = '';
    for (const s of sesses) {
        const a = s.analysis;
        const msgs = a.msgs.map(m => `<span class="mbit">${m}</span>`).join('');
        const hasV1 = s.frames.some(f => f.descVer === 1);
        sessHtml += `
        <div class="sess-item ${a.crackable ? 'crack' : ''}">
            <div style="color:var(--dim);font-size:10px;margin-bottom:4px;">STA: ${esc(s.sta)}${hasV1 ? ' <span class="yellow">[descVer=1/TKIP]</span>' : ''}</div>
            <div style="margin-bottom:4px;">${msgs}</div>
            <div style="font-size:10px;">
                ANonce <span class="${a.anonce?'green':'red'}">${a.anonce?'✓':'✗'}</span>&ensp;
                SNonce <span class="${a.snonce?'green':'red'}">${a.snonce?'✓':'✗'}</span>&ensp;
                MIC <span class="${a.micFrames.length?'green':'red'}">${a.micFrames.length?'✓ ('+a.micFrames.length+')':'✗'}</span>&ensp;
                ${a.crackable
                    ? '<span class="green">→ ready</span>'
                    : '<span class="red">→ incomplete</span>'}
            </div>
        </div>`;
    }
    document.getElementById('tgt-sessions').innerHTML = sessHtml || '<span class="dim">No sessions</span>';

    const hasV1Any = sesses.some(s => s.frames.some(f => f.descVer === 1));
    document.getElementById('descver-warn').style.display = hasV1Any ? 'block' : 'none';

    const crackable = sesses.filter(s => s.analysis.crackable);
    document.getElementById('crack-sess-info').textContent =
        crackable.length
            ? `${crackable.length} crackable session(s) — will use first available`
            : 'No crackable session found';

    document.getElementById('crack-area').style.display = 'none';
    document.getElementById('crack-result').innerHTML = '';
    document.getElementById('pbar').style.width = '0%';
    document.getElementById('pbar-text').textContent = '—';
    document.getElementById('btn-crack').disabled = !wordlistText || !net.ssid || !crackable.length;
    document.getElementById('btn-stop').disabled  = true;

    showPanel('panel-crack');
    
    addLog(`Selected target: ${esc(net.ssid || 'Unknown')} (${bssid})`, 'info');
}


// ════════════════════════════════════════════════════════════════
// ADVANCED ENGINE SETTINGS - WITH CAPABILITY DETECTION
// ════════════════════════════════════════════════════════════════

function detectEngineCaps() {
    const sab = typeof SharedArrayBuffer !== 'undefined';
    const coi = !!window.crossOriginIsolated;
    return {
        wasm: typeof WebAssembly !== 'undefined',
        sab,
        coi,
        workers: typeof Worker !== 'undefined',
        webgpu: !!(typeof navigator !== 'undefined' && navigator.gpu),
        cores: Math.max(1, Number(navigator.hardwareConcurrency || 1)),
    };
}

function bestThreadGuess(caps) {
    return Math.max(1, Math.min(8, (caps.cores || 1) > 2 ? caps.cores - 1 : 1));
}

function renderCapabilityBadges(caps) {
    const el = document.getElementById('engine-caps');
    if (!el) return;
    const items = [
        ['Worker', caps.workers],
        ['WASM', caps.wasm],
        ['SAB', caps.sab],
        ['COI', caps.coi],
        ['WebGPU', caps.webgpu],
        [`${caps.cores} CPU`, true],
    ];
    el.innerHTML = items.map(([name, ok]) =>
        `<span class="cap ${ok ? 'ok' : 'no'}">${esc(name)}</span>`).join('');
}

function updateEngineUI() {
    const modeEl = document.getElementById('crack-mode');
    const threadEl = document.getElementById('thread-count');
    const note = document.getElementById('engine-note');
    if (!modeEl || !threadEl || !note) return;

    const caps = detectEngineCaps();
    engineCaps = caps;
    renderCapabilityBadges(caps);

    const maxThreads = Math.max(1, Math.min(64, caps.cores || 1));
    threadEl.max = String(maxThreads);
    let threads = parseInt(threadEl.value || '1', 10);
    if (!Number.isFinite(threads) || threads < 1) threads = 1;
    if (threads > maxThreads) threads = maxThreads;
    threadEl.value = String(threads);
    const mode2Option = modeEl.querySelector('option[value="wasm-mt"]');
    const mode2Card = document.getElementById('mode-card-wasm');
    if (mode2Option) mode2Option.disabled = true;
    if (mode2Card) {
        mode2Card.classList.add('blocked');
        mode2Card.querySelector('.unavailable')?.remove();
        const badge = document.createElement('div');
        badge.className = 'unavailable';
        badge.textContent = 'UNDER CONSTRUCTION';
        mode2Card.insertBefore(badge, mode2Card.querySelector('.mtitle'));
    }

    const mode3Option = modeEl.querySelector('option[value="gpu-mt"]');
    const mode3Card = document.getElementById('mode-card-gpu');
    if (mode3Option) mode3Option.disabled = true;
    if (mode3Card) {
        mode3Card.classList.add('blocked');
        mode3Card.querySelector('.unavailable')?.remove();
        const badge = document.createElement('div');
        badge.className = 'unavailable';
        badge.textContent = 'UNDER CONSTRUCTION';
        mode3Card.insertBefore(badge, mode3Card.querySelector('.mtitle'));
    }

    if (crackSettings.mode !== 'js-worker') crackSettings.mode = 'js-worker';

    modeEl.value = crackSettings.mode;
    crackSettings.threads = threads;

    document.querySelectorAll('[data-mode-card]').forEach(card => {
        card.classList.toggle('active', card.dataset.modeCard === crackSettings.mode);
    });
}

function initAdvancedSettings() {
    const caps = detectEngineCaps();
    engineCaps = caps;
    renderCapabilityBadges(caps);

    const threadEl = document.getElementById('thread-count');
    const modeEl = document.getElementById('crack-mode');
    if (threadEl) threadEl.value = String(bestThreadGuess(caps));
    if (modeEl) {
        modeEl.value = 'js-worker';
        modeEl.addEventListener('change', () => {
            crackSettings.mode = modeEl.value;
            updateEngineUI();
        });
    }
    threadEl?.addEventListener('input', updateEngineUI);
    updateEngineUI();
}

// ════════════════════════════════════════════════════════════════
// WORDLIST
// ════════════════════════════════════════════════════════════════
function loadWordlist(file) {
    const r = new FileReader();
    r.onload = e => {
        wordlistText = e.target.result;
        const count = wordlistText.split('\n').filter(l => l.trim().length >= 8).length;
        document.getElementById('wl-label').textContent =
            `${file.name}  —  ${count.toLocaleString()} usable candidates (≥8 chars)`;
        document.getElementById('wl-drop').classList.add('loaded');
        addLog(`Loaded wordlist: ${file.name} (${count.toLocaleString()} candidates)`, 'success');
        if (currentTarget && currentTarget.net.ssid) {
            const crackable = currentTarget.sessions.filter(s => s.analysis.crackable);
            document.getElementById('btn-crack').disabled = crackable.length === 0;
            if (!document.getElementById('btn-crack').disabled) {
                addLog('Ready to crack. Click Start.', 'info');
            }
        }
    };
    r.readAsText(file);
}


// ════════════════════════════════════════════════════════════════
// MODE 1: JS MULTI-WORKER IMPLEMENTATION
// ════════════════════════════════════════════════════════════════
function startJsWorkerPoolCrack(payload) {
    const runId = payload.runId;
    const threads = crackSettings.threads;
    const lines = payload.wordlist.split('\n');
    const total = lines.length;
    const chunkSize = Math.ceil(total / threads);
    
    let foundPass = null;
    let completedWorkers = 0;
    let launchedWorkers = 0;
    let startTime = Date.now();
    let lastProgressUpdate = 0;
    
    // Track completed passwords per worker using Map
    const workerProgress = new Map(); // workerId -> { tried, total }
    addLog(`Mode 1: Starting ${threads} JS workers on ${total.toLocaleString()} passwords`, 'info');
    
    const blob = new Blob([WORKER_POOL_SRC], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    
    for (let w = 0; w < threads; w++) {
        const startIdx = w * chunkSize;
        const endIdx = Math.min(startIdx + chunkSize, total);
        
        if (startIdx >= total) break;
        
        const worker = new Worker(url);
        launchedWorkers++;
        crackWorkers.push(worker);
        workerProgress.set(w, { tried: 0, total: endIdx - startIdx });
        
        worker.postMessage({
            ssid: payload.ssid,
            bssid: payload.bssid,
            sta: payload.sta,
            anonce: payload.anonce,
            snonce: payload.snonce,
            micFrames: payload.micFrames,
            wordlist: payload.wordlist,
            startIdx,
            endIdx,
            workerId: w
        });
        
        worker.onmessage = e => {
            if (!crackActive || runId !== crackRunId) return;
            const d = e.data;
            if (d.type === 'found') {
                foundPass = d.password;
                workerProgress.set(d.workerId, { tried: d.tried, total: d.total });
                let totalTried = 0;
                workerProgress.forEach(p => totalTried += p.tried);
                stopAllWorkers();
                addLog(`PASSWORD FOUND: ${d.password}`, 'success');
                handleCrackResult({
                    type: 'found',
                    password: d.password,
                    tried: totalTried,
                    total: total,
                    elapsed: (Date.now() - startTime) / 1000
                });
            } else if (d.type === 'progress') {
                workerProgress.set(d.workerId, { tried: d.tried, total: d.total });
                
                // Throttle UI updates (max 10 times per second)
                const now = Date.now();
                if (now - lastProgressUpdate < 100) return;
                lastProgressUpdate = now;
                
                // Calculate total tried across all workers
                let totalTried = 0;
                workerProgress.forEach(p => totalTried += p.tried);
                setProgress(totalTried, total, startTime);
            } else if (d.type === 'done') {
                workerProgress.set(d.workerId, { tried: d.tried, total: d.total });
                completedWorkers++;
                addLog(`Worker ${d.workerId} completed (${d.tried} passwords)`, 'info');
                if (completedWorkers === launchedWorkers && !foundPass) {
                    let totalTried = 0;
                    workerProgress.forEach(p => totalTried += p.tried);
                    addLog(`All workers finished. Password not found.`, 'warn');
                    handleCrackResult({
                        type: 'done',
                        tried: totalTried,
                        total: total,
                        elapsed: (Date.now() - startTime) / 1000
                    });
                }
            }
        };
        
        worker.onerror = err => {
            if (!crackActive || runId !== crackRunId) return;
            document.getElementById('pbar-text').textContent = `Worker error: ${err.message}`;
            crackFinish();
        };
    }
    
    URL.revokeObjectURL(url);
}

// ════════════════════════════════════════════════════════════════
// MODE 1: SINGLE WORKER WITH ETA
// ════════════════════════════════════════════════════════════════
function startSingleWorkerCrack(payload) {
    const runId = payload.runId;
    const blob = new Blob([WORKER_SRC], { type: 'application/javascript' });
    const url  = URL.createObjectURL(blob);
    singleWorker = new Worker(url);
    crackWorkers.push(singleWorker);
    
    const lineCount = wordlistText.split('\n').length;
    addLog(`Starting single worker for ${lineCount} passwords...`, 'info');
    singleWorker.postMessage(payload);
    
    let startTime = Date.now();
    
    singleWorker.onmessage = e => {
        if (!crackActive || runId !== crackRunId) return;
        const d = e.data;
        if (d.type === 'found') {
            addLog(`PASSWORD FOUND: ${d.password}`, 'success');
            handleCrackResult({
                type: 'found',
                password: d.password,
                tried: d.tried,
                total: d.total,
                elapsed: (Date.now() - startTime) / 1000
            });
        } else if (d.type === 'progress') {
            setProgress(d.tried, d.total, startTime);
        } else if (d.type === 'done') {
            addLog(`All passwords checked. Password not found.`, 'warn');
            handleCrackResult({
                type: 'done',
                tried: d.tried,
                total: d.total,
                elapsed: (Date.now() - startTime) / 1000
            });
        }
    };
    singleWorker.onerror = err => {
        if (!crackActive || runId !== crackRunId) return;
        document.getElementById('pbar-text').textContent = `Worker error: ${err.message}`;
        addLog(`Worker error: ${err.message}`, 'error');
        crackFinish();
    };
    
    URL.revokeObjectURL(url);
}

// ════════════════════════════════════════════════════════════════
// MODE 2: WASM BACKEND STUB
// ════════════════════════════════════════════════════════════════
const WASM_MT_BACKEND = null;
function runWasmMtCrack(_payload) {
    return Promise.resolve({ type:'error', message:'Mode 2 WASM multithreading under construction' });
}

// ════════════════════════════════════════════════════════════════
// MODE 3: WEBGPU BACKEND STUB
// ════════════════════════════════════════════════════════════════
const WEBGPU_BACKEND = null;
function runWebGpuCrack(_payload) {
    return Promise.resolve({ type:'error', message:'Mode 3 WebGPU under construction' });
}

// ════════════════════════════════════════════════════════════════
// CRACK ENTRY POINT
// ════════════════════════════════════════════════════════════════
function startCrack() {
    if (!currentTarget || !wordlistText) return;
    if (!currentTarget.net.ssid) { alert('SSID unknown — cannot derive PMK without SSID'); return; }

    const crackable = currentTarget.sessions.filter(s => s.analysis.crackable);
    if (!crackable.length) { alert('No crackable session'); return; }

    updateEngineUI();

    const sess = crackable[0];
    const a    = sess.analysis;
    const payload = {
        ssid:      currentTarget.net.ssid,
        bssid:     sess.bssid,
        sta:       sess.sta,
        anonce:    Array.from(a.anonce),
        snonce:    Array.from(a.snonce),
        micFrames: a.micFrames.map(f => ({ eapol: f.eapol, descVer: f.descVer, mic: f.mic })),
        wordlist:  wordlistText,
        engine:    { ...crackSettings },
    };

    if (crackSettings.mode === 'wasm-mt') {
        document.getElementById('crack-area').style.display = 'block';
        document.getElementById('pbar').style.width = '0%';
        document.getElementById('pbar-text').textContent = 'Mode 2 WASM multithreading under construction';
        document.getElementById('crack-result').innerHTML = '<div class="result-info">Mode 2 WASM multithreading under construction</div>';
        document.getElementById('btn-crack').disabled = false;
        document.getElementById('btn-stop').disabled = true;
        return;
    }

    if (crackSettings.mode === 'gpu-mt') {
        document.getElementById('crack-area').style.display = 'block';
        document.getElementById('pbar').style.width = '0%';
        document.getElementById('pbar-text').textContent = 'Mode 3 WebGPU under construction';
        document.getElementById('crack-result').innerHTML = '<div class="result-info">Mode 3 WebGPU under construction</div>';
        document.getElementById('btn-crack').disabled = false;
        document.getElementById('btn-stop').disabled = true;
        return;
    }

    document.getElementById('crack-area').style.display = 'block';
    document.getElementById('crack-result').innerHTML = '';
    document.getElementById('pbar').style.width = '0%';
    document.getElementById('pbar-text').textContent = 'Starting...';
    document.getElementById('btn-crack').disabled = true;
    document.getElementById('btn-stop').disabled  = false;

    crackStartTime = Date.now();
    crackActive = true;
    payload.runId = ++crackRunId;

    try {
        startJsWorkerPoolCrack(payload);
    } catch(err) {
        document.getElementById('pbar-text').textContent = `Error: ${err.message}`;
        crackFinish();
    }
}

function handleCrackResult(d) {
    const elapsed = d.elapsed || ((Date.now() - crackStartTime) / 1000);
    const rate = elapsed > 0 ? Math.round(d.tried / elapsed) : 0;
    const pct  = d.total > 0 ? (d.tried / d.total * 100).toFixed(2) : '?';

    if (d.type === 'progress') {
        setProgress(d.tried, d.total, crackStartTime);

    } else if (d.type === 'found') {
        document.getElementById('pbar').style.width = '100%';
        document.getElementById('pbar-text').textContent =
            `Found after ${d.tried.toLocaleString()} attempts in ${d.elapsed.toFixed(1)}s  (${rate.toLocaleString()} pwd/s)`;
        document.getElementById('crack-result').innerHTML =
            `<div class="result-ok">&#x1F511; PASSWORD FOUND&emsp;<strong>${esc(d.password)}</strong></div>`;
        addLog(`SUCCESS: Password found after ${d.tried} attempts in ${d.elapsed.toFixed(1)}s`, 'success');
        crackFinish();

    } else if (d.type === 'done') {
        document.getElementById('pbar').style.width = '100%';
        document.getElementById('pbar-text').textContent =
            `Exhausted ${d.total.toLocaleString()} candidates in ${d.elapsed.toFixed(1)}s`;
        document.getElementById('crack-result').innerHTML =
            `<div class="result-no">Password not found in wordlist</div>`;
        addLog(`FAILED: All ${d.total} passwords checked. Password not found.`, 'warn');
        crackFinish();
    } else if (d.type === 'error') {
        document.getElementById('pbar-text').textContent = `Error: ${d.message}`;
        addLog(`Error: ${d.message}`, 'error');
        crackFinish();
    }
}

// ════════════════════════════════════════════════════════════════
// STOP CRACK - ENSURE ALL WORKERS ARE STOPPED
// ════════════════════════════════════════════════════════════════
function stopCrack() {
    crackActive = false;
    crackRunId++;
    stopAllWorkers();
    document.getElementById('pbar-text').textContent = 'Stopped';
    document.getElementById('btn-crack').disabled = false;
    document.getElementById('btn-stop').disabled  = true;
}

function stopAllWorkers() {
    const workers = new Set(crackWorkers);
    if (singleWorker) workers.add(singleWorker);
    for (const w of workers) {
        try {
            w.onmessage = null;
            w.onerror = null;
            w.onmessageerror = null;
            w.terminate();
        } catch(e) {}
    }
    crackWorkers = [];
    singleWorker = null;
}

function crackFinish() {
    crackActive = false;
    crackRunId++;
    stopAllWorkers();
    document.getElementById('btn-crack').disabled = false;
    document.getElementById('btn-stop').disabled  = true;
}

// ════════════════════════════════════════════════════════════════
// FILE INPUT / DRAG-DROP
// ════════════════════════════════════════════════════════════════
function handlePcap(file) {
    if (!file) return;
    setStatus(`Parsing ${file.name}…`);
    addLog(`Loading ${file.name}...`, 'info');
    const r = new FileReader();
    r.onload = e => {
        try {
            G = analyzePcap(e.target.result);
            const sessCount = Object.keys(G.sessions).length;
            const netCount  = Object.keys(G.nets).length;
            setStatus(
                `${file.name}  —  ${G.pktCount.toLocaleString()} packets, ${G.dot11Count.toLocaleString()} 802.11 frames`,
                `${netCount} AP${netCount!==1?'s':''}, ${sessCount} EAPOL session${sessCount!==1?'s':''}`
            );
            addLog(`Parsed ${G.pktCount} packets, ${netCount} APs, ${sessCount} sessions`, 'success');
            renderAPTable();
            showPanel('panel-aps');
        } catch(err) {
            setStatus(`Error: ${err.message}`);
            addLog(`Parse error: ${err.message}`, 'error');
            alert(err.message);
        }
    };
    r.readAsArrayBuffer(file);
}

// ── PCAP drop zone ──
const dropZone  = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
dropZone.addEventListener('click',     () => fileInput.click());
dropZone.addEventListener('dragover',  e  => { e.preventDefault(); dropZone.classList.add('over'); });
dropZone.addEventListener('dragleave', () => { dropZone.classList.remove('over'); });
dropZone.addEventListener('drop',      e  => { e.preventDefault(); dropZone.classList.remove('over'); handlePcap(e.dataTransfer.files[0]); });
fileInput.addEventListener('change',   () => fileInput.files[0] && handlePcap(fileInput.files[0]));

// ── Wordlist drop zone ──
const wlDrop  = document.getElementById('wl-drop');
const wlInput = document.getElementById('wl-input');
wlDrop.addEventListener('dragover',  e  => { e.preventDefault(); wlDrop.classList.add('loaded'); });
wlDrop.addEventListener('dragleave', () => { if (!wordlistText) wlDrop.classList.remove('loaded'); });
wlDrop.addEventListener('drop',      e  => { e.preventDefault(); loadWordlist(e.dataTransfer.files[0]); });
wlInput.addEventListener('change',   () => wlInput.files[0] && loadWordlist(wlInput.files[0]));

// Initialize
initAdvancedSettings();
addLog('WiFi PCAP Analyzer ready. Drop a .pcap file to begin.', 'info');
