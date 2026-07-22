// api/scan.js — PetalScan backend (Vercel serverless function)
// Passive security-posture check: reads the HTTP response headers a website
// already serves to every visitor, then grades common best practices.
// It does NOT probe, inject, brute-force, or exploit anything.

const UA = 'PetalScan/1.0 (+passive security-headers check)';

function isBlockedHost(host) {
  host = (host || '').toLowerCase();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '[::1]') return true;
  // block bare IPv4 in private / loopback / link-local ranges
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true; // link-local / cloud metadata
  }
  return false;
}

async function fetchWithTimeout(url, opts, ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  try {
    return await fetch(url, Object.assign({ signal: c.signal }, opts));
  } finally {
    clearTimeout(t);
  }
}

export default async function handler(req, res) {
  const raw = (req.query.url || '').toString().trim();
  if (!raw) return res.status(400).json({ error: 'Alamat website masih kosong.' });

  let target;
  try {
    target = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw);
  } catch (e) {
    return res.status(200).json({ error: 'Alamat website tidak valid.' });
  }
  if (!/^https?:$/.test(target.protocol)) {
    return res.status(200).json({ error: 'Hanya mendukung http/https.' });
  }
  if (isBlockedHost(target.hostname)) {
    return res.status(200).json({ error: 'Alamat internal/privat tidak boleh dipindai.' });
  }

  let resp;
  try {
    resp = await fetchWithTimeout(target.href, {
      redirect: 'follow',
      headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' }
    }, 8000);
  } catch (err) {
    return res.status(200).json({
      error: 'Website tidak bisa dijangkau (mungkin down, memblokir, atau lambat).'
    });
  }

  const h = resp.headers;
  const get = (k) => h.get(k) || '';
  const finalUrl = resp.url || target.href;
  const servedHttps = (() => { try { return new URL(finalUrl).protocol === 'https:'; } catch (e) { return false; } })();

  // Does plain http:// get redirected to https?
  let httpRedirects = false;
  try {
    const httpUrl = 'http://' + target.hostname + (target.pathname || '/');
    const r2 = await fetchWithTimeout(httpUrl, {
      redirect: 'manual',
      headers: { 'User-Agent': UA }
    }, 6000);
    const loc = r2.headers.get('location') || '';
    httpRedirects = r2.status >= 300 && r2.status < 400 && /^https:/i.test(loc);
  } catch (e) { /* ignore — not decisive */ }

  let score = 0, max = 0;
  const groups = [];
  const add = (arr, status, label, detail, weight) => {
    weight = weight || 1;
    if (status !== 'skip') max += weight;
    if (status === 'pass') score += weight;
    if (status === 'warn') score += weight * 0.5;
    if (status !== 'skip') arr.push({ status, label, detail });
  };

  // --- Koneksi aman ---
  const conn = [];
  add(conn, servedHttps ? 'pass' : 'fail', servedHttps ? 'HTTPS aktif' : 'HTTPS tidak aktif',
    servedHttps ? 'Website dienkripsi, data pengunjung tidak gampang diintip.'
                : 'Website tidak pakai HTTPS — data bisa disadap di jaringan.', 3);
  add(conn, httpRedirects ? 'pass' : 'fail', httpRedirects ? 'HTTP dialihkan ke HTTPS' : 'HTTP tidak dipaksa ke HTTPS',
    httpRedirects ? 'Buka pakai http:// otomatis diarahkan ke versi aman.'
                  : 'Pengunjung yang buka http:// bisa tertinggal di koneksi tidak aman.', 1);
  const hsts = get('strict-transport-security');
  add(conn, hsts ? 'pass' : 'fail', hsts ? 'HSTS aktif' : 'HSTS belum ada',
    hsts ? 'Browser diinstruksikan selalu memakai koneksi aman.'
         : 'Tambahkan Strict-Transport-Security agar browser selalu pilih HTTPS.', 2);
  groups.push({ title: '🔒 Koneksi aman', items: conn });

  // --- Perlindungan browser ---
  const prot = [];
  const csp = get('content-security-policy');
  add(prot, csp ? 'pass' : 'fail', csp ? 'Content-Security-Policy ada' : 'Content-Security-Policy belum ada',
    csp ? 'Sumber konten dibatasi — pertahanan bagus melawan XSS.'
        : 'Tanpa CSP, website lebih rawan serangan XSS (penyusupan script).', 2);
  const xcto = get('x-content-type-options').toLowerCase();
  add(prot, xcto.indexOf('nosniff') > -1 ? 'pass' : 'fail', 'Anti-sniff tipe file',
    xcto.indexOf('nosniff') > -1 ? 'X-Content-Type-Options: nosniff sudah dipasang.'
                                 : 'Pasang X-Content-Type-Options: nosniff.', 1);
  const xfo = get('x-frame-options');
  const frameAnc = /frame-ancestors/i.test(csp);
  add(prot, (xfo || frameAnc) ? 'pass' : 'fail', 'Perlindungan clickjacking',
    (xfo || frameAnc) ? 'Website tidak bisa di-embed diam-diam di iframe orang lain.'
                      : 'Rawan clickjacking — pakai X-Frame-Options atau frame-ancestors di CSP.', 1);
  const refp = get('referrer-policy');
  add(prot, refp ? 'pass' : 'warn', refp ? 'Referrer-Policy diatur' : 'Referrer-Policy longgar',
    refp ? 'Kebocoran alamat asal dibatasi.' : 'Sebaiknya batasi info alamat asal yang dibocorkan ke situs lain.', 1);
  const permp = get('permissions-policy') || get('feature-policy');
  add(prot, permp ? 'pass' : 'warn', permp ? 'Permissions-Policy diatur' : 'Permissions-Policy belum ada',
    permp ? 'Akses fitur sensitif (kamera, lokasi) dibatasi.' : 'Batasi akses fitur browser lewat Permissions-Policy.', 1);
  groups.push({ title: '🛡️ Perlindungan browser', items: prot });

  // --- Cookie ---
  const cookie = [];
  const setCookie = (typeof h.getSetCookie === 'function' ? h.getSetCookie().join(' ; ') : get('set-cookie'));
  if (setCookie) {
    const low = setCookie.toLowerCase();
    const missing = [];
    if (low.indexOf('secure') === -1) missing.push('Secure');
    if (low.indexOf('httponly') === -1) missing.push('HttpOnly');
    if (low.indexOf('samesite') === -1) missing.push('SameSite');
    if (missing.length === 0) add(cookie, 'pass', 'Cookie terlindungi', 'Pakai flag Secure, HttpOnly, dan SameSite.', 1);
    else add(cookie, 'warn', 'Flag cookie kurang', 'Cookie belum memakai: ' + missing.join(', ') + '.', 1);
  } else {
    add(cookie, 'pass', 'Tidak ada cookie di-set', 'Tidak ada cookie pada respons ini — tidak ada yang perlu diamankan di sini.', 1);
  }
  groups.push({ title: '🍪 Cookie', items: cookie });

  // --- Kebocoran info ---
  const leak = [];
  const server = get('server');
  const powered = get('x-powered-by');
  const disclosed = [server, powered].filter(Boolean).filter((v) => /\d/.test(v));
  if (disclosed.length) {
    add(leak, 'warn', 'Versi software terlihat', 'Header membocorkan "' + disclosed.join('", "') + '" — sembunyikan biar tidak jadi petunjuk penyerang.', 1);
  } else {
    add(leak, 'pass', 'Versi software tidak diumbar', 'Header tidak membocorkan versi server yang spesifik.', 1);
  }
  groups.push({ title: '🔎 Kebocoran info', items: leak });

  const pct = score / max;
  const grade = pct >= 0.9 ? 'A' : pct >= 0.75 ? 'B' : pct >= 0.6 ? 'C' : pct >= 0.4 ? 'D' : 'F';

  return res.status(200).json({
    url: raw,
    finalUrl,
    grade,
    score: Math.round(score),
    maxScore: max,
    groups
  });
}
