// api/scan.js — PetalScan backend (Vercel serverless, Node.js runtime)
// Passive security-posture check: headers, SSL certificate, DNS/public info.
// It only reads what a site already exposes to any visitor. It does NOT probe,
// inject, brute-force, or exploit. Requests are bounded (a handful, once per click).

import tls from 'node:tls';
import dns from 'node:dns';

const UA = 'PetalScan/2.0 (+passive security check)';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function isBlockedHost(host) {
  host = (host || '').toLowerCase();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host === '::1' || host === '[::1]') return true;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 127 || a === 10 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
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

function tlsInfo(host, ms) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; try { socket.destroy(); } catch (e) {} resolve(v); } };
    const socket = tls.connect(
      { host, port: 443, servername: host, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;
        if (!cert || !cert.valid_to) return finish({ ok: false });
        const to = new Date(cert.valid_to);
        const daysLeft = Math.floor((to.getTime() - Date.now()) / 86400000);
        const issuer = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || 'tidak diketahui';
        const subject = (cert.subject && cert.subject.CN) || host;
        finish({ ok: true, authorized, authError: authError ? String(authError) : null, daysLeft, issuer, subject, validTo: to.toDateString() });
      }
    );
    socket.setTimeout(ms, () => finish({ ok: false, timeout: true }));
    socket.on('error', () => finish({ ok: false }));
  });
}

async function dnsInfo(host, ms) {
  const work = (async () => {
    const out = { a: [], cname: null };
    try { out.a = await dns.promises.resolve4(host); } catch (e) {}
    try { const cn = await dns.promises.resolveCname(host); out.cname = cn && cn[0]; } catch (e) {}
    return out;
  })();
  const timeout = new Promise((res) => setTimeout(() => res({ a: [], cname: null, timeout: true }), ms));
  return Promise.race([work, timeout]);
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
  if (!/^https?:$/.test(target.protocol)) return res.status(200).json({ error: 'Hanya mendukung http/https.' });
  if (isBlockedHost(target.hostname)) return res.status(200).json({ error: 'Alamat internal/privat tidak boleh dipindai.' });

  // Run the passive checks with a tiny stagger (so it's not one simultaneous burst),
  // each with its own timeout, all capped in parallel to stay well under Vercel's limit.
  const host = target.hostname;
  const getHeaders = (async () => {
    try {
      return await fetchWithTimeout(target.href, { redirect: 'follow', headers: { 'User-Agent': UA, 'Accept': 'text/html,*/*' } }, 6000);
    } catch (e) { return null; }
  })();
  const getRedirect = (async () => {
    await sleep(120);
    try {
      const r2 = await fetchWithTimeout('http://' + host + (target.pathname || '/'), { redirect: 'manual', headers: { 'User-Agent': UA } }, 5000);
      const loc = r2.headers.get('location') || '';
      return r2.status >= 300 && r2.status < 400 && /^https:/i.test(loc);
    } catch (e) { return false; }
  })();
  const getSsl = (async () => { await sleep(80); return tlsInfo(host, 5000); })();
  const getDns = (async () => { await sleep(160); return dnsInfo(host, 3000); })();

  const [resp, httpRedirects, ssl, dnsRes] = await Promise.all([getHeaders, getRedirect, getSsl, getDns]);

  if (!resp) return res.status(200).json({ error: 'Website tidak bisa dijangkau (mungkin down, memblokir, atau lambat).' });

  const h = resp.headers;
  const get = (k) => h.get(k) || '';
  const finalUrl = resp.url || target.href;
  const servedHttps = (() => { try { return new URL(finalUrl).protocol === 'https:'; } catch (e) { return false; } })();

  let score = 0, max = 0;
  const groups = [];
  const add = (arr, status, label, detail, weight) => {
    weight = weight || 1;
    if (status === 'info') { arr.push({ status, label, detail }); return; }
    if (status !== 'skip') max += weight;
    if (status === 'pass') score += weight;
    if (status === 'warn') score += weight * 0.5;
    if (status !== 'skip') arr.push({ status, label, detail });
  };

  // --- Koneksi aman ---
  const conn = [];
  add(conn, servedHttps ? 'pass' : 'fail', servedHttps ? 'HTTPS aktif' : 'HTTPS tidak aktif',
    servedHttps ? 'Website dienkripsi, data pengunjung tidak gampang diintip.' : 'Website tidak pakai HTTPS — data bisa disadap di jaringan.', 3);
  add(conn, httpRedirects ? 'pass' : 'fail', httpRedirects ? 'HTTP dialihkan ke HTTPS' : 'HTTP tidak dipaksa ke HTTPS',
    httpRedirects ? 'Buka pakai http:// otomatis diarahkan ke versi aman.' : 'Pengunjung yang buka http:// bisa tertinggal di koneksi tidak aman.', 1);
  const hsts = get('strict-transport-security');
  add(conn, hsts ? 'pass' : 'fail', hsts ? 'HSTS aktif' : 'HSTS belum ada',
    hsts ? 'Browser diinstruksikan selalu memakai koneksi aman.' : 'Tambahkan Strict-Transport-Security agar browser selalu pilih HTTPS.', 2);
  groups.push({ title: '🔒 Koneksi aman', items: conn });

  // --- Sertifikat SSL ---
  const cert = [];
  if (ssl && ssl.ok) {
    if (ssl.daysLeft <= 0) {
      add(cert, 'fail', 'Sertifikat kedaluwarsa', 'Sertifikat SSL sudah lewat masa berlaku — browser bakal kasih peringatan ke pengunjung.', 2);
    } else if (ssl.authError) {
      add(cert, 'warn', 'Sertifikat bermasalah', 'Rantai sertifikat tidak tepercaya (' + ssl.authError + ') — cek pemasangannya.', 2);
    } else if (ssl.daysLeft <= 21) {
      add(cert, 'warn', 'Sertifikat mau kedaluwarsa', 'Tinggal ' + ssl.daysLeft + ' hari lagi — segera perpanjang sebelum jatuh tempo.', 2);
    } else {
      add(cert, 'pass', 'Sertifikat SSL sehat', 'Valid dan masih lama — sisa ' + ssl.daysLeft + ' hari (berlaku s/d ' + ssl.validTo + ').', 2);
    }
    add(cert, 'info', 'Penerbit', ssl.issuer + ' · untuk ' + ssl.subject);
  } else {
    add(cert, 'fail', 'Tidak ada sertifikat SSL', (ssl && ssl.timeout) ? 'Koneksi TLS timeout saat mengambil sertifikat.' : 'Tidak bisa ambil sertifikat di port 443 — kemungkinan situs hanya http.', 2);
  }
  groups.push({ title: '📜 Sertifikat SSL', items: cert });

  // --- Perlindungan browser ---
  const prot = [];
  const csp = get('content-security-policy');
  add(prot, csp ? 'pass' : 'fail', csp ? 'Content-Security-Policy ada' : 'Content-Security-Policy belum ada',
    csp ? 'Sumber konten dibatasi — pertahanan bagus melawan XSS.' : 'Tanpa CSP, website lebih rawan serangan XSS (penyusupan script).', 2);
  const xcto = get('x-content-type-options').toLowerCase();
  add(prot, xcto.indexOf('nosniff') > -1 ? 'pass' : 'fail', 'Anti-sniff tipe file',
    xcto.indexOf('nosniff') > -1 ? 'X-Content-Type-Options: nosniff sudah dipasang.' : 'Pasang X-Content-Type-Options: nosniff.', 1);
  const xfo = get('x-frame-options');
  const frameAnc = /frame-ancestors/i.test(csp);
  add(prot, (xfo || frameAnc) ? 'pass' : 'fail', 'Perlindungan clickjacking',
    (xfo || frameAnc) ? 'Website tidak bisa di-embed diam-diam di iframe orang lain.' : 'Rawan clickjacking — pakai X-Frame-Options atau frame-ancestors di CSP.', 1);
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

  // --- Info publik / DNS (informasional, tidak memengaruhi nilai) ---
  const info = [];
  if (dnsRes && dnsRes.a && dnsRes.a.length) add(info, 'info', 'Alamat IP', dnsRes.a.slice(0, 3).join(', '));
  if (dnsRes && dnsRes.cname) add(info, 'info', 'CNAME', dnsRes.cname + ' (indikasi CDN/hosting)');
  if (!info.length) add(info, 'info', 'DNS', 'Tidak ada data DNS publik yang bisa diambil.');
  groups.push({ title: '🌐 Info publik', items: info });

  // --- Kebocoran info ---
  const leak = [];
  const disclosed = [get('server'), get('x-powered-by')].filter(Boolean).filter((v) => /\d/.test(v));
  if (disclosed.length) add(leak, 'warn', 'Versi software terlihat', 'Header membocorkan "' + disclosed.join('", "') + '" — sembunyikan biar tidak jadi petunjuk penyerang.', 1);
  else add(leak, 'pass', 'Versi software tidak diumbar', 'Header tidak membocorkan versi server yang spesifik.', 1);
  groups.push({ title: '🔎 Kebocoran info', items: leak });

  const pct = score / max;
  const grade = pct >= 0.9 ? 'A' : pct >= 0.75 ? 'B' : pct >= 0.6 ? 'C' : pct >= 0.4 ? 'D' : 'F';

  return res.status(200).json({ url: raw, finalUrl, grade, score: Math.round(score), maxScore: max, groups });
}
