'use strict';
/*
 * نظام خطوط السير — السويدي إيجيتك
 * Employee transport-lines registration system.
 * Node 22+. Only dependency: pg (used when DATABASE_URL is set, e.g. on Render + Neon).
 * Without DATABASE_URL it keeps state in a local data.json file.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DATA_FILE = path.join(__dirname, 'data.json');
const SEED_FILE = path.join(__dirname, 'seed-lines.json');
const ADMIN_USER = process.env.ADMIN_USERNAME || 'ibrahim';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || '';

/* ---------------- state ---------------- */
let state = null; // { lines:[{id,name,time,price,driver,driverId,active,stops:[{id,name}]}], riders:[...], users:[...] }
let saveTimer = null;
let pgPool = null;

function uid(prefix) { return prefix + crypto.randomBytes(8).toString('hex'); }

const DEFAULT_COMPANIES = ['المتحدة للصناعات', 'الألمونيوم', 'الهندسية', 'إيجيتك', 'الاسلاك', 'بيدي وير', 'العربيه الكابلات', 'بروفيشنال'];

function seedState() {
  const seed = JSON.parse(fs.readFileSync(SEED_FILE, 'utf8'));
  const lines = seed.map((l, i) => ({
    id: uid('L'), name: l.sheet, time: l.time || '', price: l.price || '',
    driver: l.driver || '', driverId: l.driver_id || '',
    active: true, position: i,
    stops: l.stops.map((s, j) => ({ id: uid('S'), name: s, position: j }))
  }));
  return { lines, riders: [], users: [], seededAt: new Date().toISOString() };
}

function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return salt + ':' + h;
}
function verifyPw(pw, stored) {
  try {
    const [salt, h] = String(stored).split(':');
    const calc = crypto.scryptSync(String(pw), salt, 32);
    return crypto.timingSafeEqual(calc, Buffer.from(h, 'hex'));
  } catch (e) { return false; }
}

function ensureAdmin() {
  if (!state.users.length) {
    const pass = ADMIN_PASS || crypto.randomBytes(6).toString('hex');
    state.users.push({ id: uid('U'), username: ADMIN_USER, passHash: hashPw(pass), role: 'admin', createdAt: new Date().toISOString() });
    if (!ADMIN_PASS) console.log('=== GENERATED ADMIN LOGIN ===', ADMIN_USER, '/', pass);
    saveSoon();
  }
}

/* ---------------- persistence ---------------- */
async function initPg() {
  if (!process.env.DATABASE_URL) return false;
  const { Pool } = require('pg');
  pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 3 });
  await pgPool.query('CREATE TABLE IF NOT EXISTS kv (id TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())');
  return true;
}
async function loadState() {
  if (pgPool) {
    const r = await pgPool.query("SELECT data FROM kv WHERE id='state'");
    if (r.rows.length) return r.rows[0].data;
    return null;
  }
  if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  return null;
}
function saveSoon() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { saveTimer = null; saveNow().catch(e => console.error('save failed', e)); }, 400);
}
async function saveNow() {
  const snap = JSON.stringify(state);
  if (pgPool) {
    await pgPool.query("INSERT INTO kv (id,data,updated_at) VALUES ('state',$1::jsonb,now()) ON CONFLICT (id) DO UPDATE SET data=$1::jsonb, updated_at=now()", [snap]);
  } else {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, snap, { mode: 0o600 });
    fs.renameSync(tmp, DATA_FILE);
  }
}

/* ---------------- sessions ---------------- */
const sessions = new Map(); // token -> {userId, exp}
function newSession(userId) {
  const t = crypto.randomBytes(24).toString('hex');
  sessions.set(t, { userId, exp: Date.now() + 30 * 24 * 3600 * 1000 });
  return t;
}
function sessionUser(req) {
  const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const s = sessions.get(m[1]);
  if (!s || s.exp < Date.now()) return null;
  return state.users.find(u => u.id === s.userId) || null;
}

/* ---------------- http helpers ---------------- */
function readBody(req) {
  return new Promise((res, rej) => {
    let b = ''; req.on('data', c => { b += c; if (b.length > 1e6) req.destroy(); });
    req.on('end', () => { try { res(b ? JSON.parse(b) : {}); } catch (e) { rej(e); } });
    req.on('error', rej);
  });
}
function send(res, code, obj, headers) {
  const body = typeof obj === 'string' || Buffer.isBuffer(obj) ? obj : JSON.stringify(obj);
  res.writeHead(code, Object.assign({ 'Content-Type': typeof obj === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers || {}));
  res.end(body);
}
const clean = (v, max) => String(v == null ? '' : v).trim().slice(0, max || 120);

/* ---- input cleaning & validation (mass registration) ---- */
function cleanName(v) {
  let s = String(v == null ? '' : v);
  s = s.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  s = s.replace(/[^\u0600-\u06FFa-zA-Z0-9 .\-']/g, '').replace(/\s+/g, ' ').trim();
  if (s.length > 120) s = s.slice(0, 120).trim();
  return s;
}
function validName(s) {
  // triple name required: at least 3 words, each word a real word (2+ letters)
  const words = s.split(' ').filter(Boolean);
  if (words.length < 3) return false;
  return words.every(w => (w.match(/[\u0600-\u06FFa-zA-Z]/g) || []).length >= 2);
}
const AR_DIGITS = { '٠': '0', '١': '1', '٢': '2', '٣': '3', '٤': '4', '٥': '5', '٦': '6', '٧': '7', '٨': '8', '٩': '9', '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4', '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9' };
function cleanCode(v) {
  // codes stored in Latin digits: Arabic-Indic digits typed by the employee are converted
  return String(v == null ? '' : v).replace(/[٠-٩۰-۹]/g, d => AR_DIGITS[d])
    .replace(/\s+/g, '').replace(/[\u0000-\u001F\u007F]/g, '').slice(0, 20);
}
function validCode(s) { return /^[0-9]{2,20}$/.test(s); } // digits only; Arabic-Indic digits already converted by cleanCode

/* per-IP rate limit for public registration (60 per 10 min — generous on purpose:
   employees may register together from one office PC or shared company network) */
const regHits = new Map(); // ip -> [timestamps]
function regAllowed(req) {
  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '?';
  const now = Date.now(); const win = 10 * 60 * 1000;
  const arr = (regHits.get(ip) || []).filter(t => now - t < win);
  if (arr.length >= 60) { regHits.set(ip, arr); return false; } // generous: shared company networks/PCs share one IP
  arr.push(now); regHits.set(ip, arr);
  if (regHits.size > 5000) regHits.clear();
  return true;
}

/* ---------------- public API ---------------- */
function publicLines() {
  return state.lines.filter(l => l.active).sort((a, b) => a.position - b.position)
    .map(l => ({ id: l.id, name: l.name, time: l.time, stops: l.stops.map(s => ({ id: s.id, name: s.name })) }));
}

/* ---------------- xlsx export (minimal, zero-dep) ---------------- */
function crc32(buf) {
  let table = crc32.t;
  if (!table) {
    table = crc32.t = new Int32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; table[n] = c; }
  }
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ table[(c ^ buf[i]) & 0xFF];
  return (c ^ -1) >>> 0;
}
function buildXlsx(sheetName, rows) {
  // rows: array of arrays of strings
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  let sheetRows = '';
  rows.forEach((r, ri) => {
    sheetRows += `<row r="${ri + 1}">` + r.map((c, ci) => {
      const ref = String.fromCharCode(65 + ci) + (ri + 1);
      return `<c r="${ref}" t="inlineStr"><is><t>${esc(c)}</t></is></c>`;
    }).join('') + '</row>';
  });
  const sheetXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView rightToLeft="1" workbookViewId="0"/></sheetViews><sheetData>${sheetRows}</sheetData></worksheet>`;
  const wbXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${esc(sheetName).slice(0, 31)}" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const relsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`;
  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const ctXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`;
  const files = [
    ['[Content_Types].xml', ctXml], ['_rels/.rels', rootRels],
    ['xl/workbook.xml', wbXml], ['xl/_rels/workbook.xml.rels', relsXml], ['xl/worksheets/sheet1.xml', sheetXml]
  ];
  const parts = []; let offset = 0; const central = [];
  for (const [name, content] of files) {
    const nb = Buffer.from(name, 'utf8'); const cb = Buffer.from(content, 'utf8'); const crc = crc32(cb);
    const head = Buffer.alloc(30);
    head.writeUInt32LE(0x04034b50, 0); head.writeUInt16LE(20, 4); head.writeUInt16LE(0x0800, 6); head.writeUInt16LE(0, 8);
    head.writeUInt16LE(0, 10); head.writeUInt16LE(0, 12); head.writeUInt32LE(crc, 14);
    head.writeUInt32LE(cb.length, 18); head.writeUInt32LE(cb.length, 22); head.writeUInt16LE(nb.length, 26); head.writeUInt16LE(0, 28);
    parts.push(head, nb, cb);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0); cen.writeUInt16LE(20, 4); cen.writeUInt16LE(20, 6); cen.writeUInt16LE(0x0800, 8);
    cen.writeUInt32LE(crc, 16); cen.writeUInt32LE(cb.length, 20); cen.writeUInt32LE(cb.length, 24);
    cen.writeUInt16LE(nb.length, 28); cen.writeUInt32LE(offset, 42);
    central.push(Buffer.concat([cen, nb]));
    offset += 30 + nb.length + cb.length;
  }
  const cd = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...parts, cd, end]);
}

/* ---------------- routes ---------------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' };

async function handle(req, res) {
  const u = new URL(req.url, 'http://x');
  const p = u.pathname;

  if (p === '/api/health') return send(res, 200, { ok: true });

  // public: active lines + stops
  if (p === '/api/public/lines') return send(res, 200, { lines: publicLines(), companies: state.companies });

  // public: register
  if (p === '/api/public/register' && req.method === 'POST') {
    if (!regAllowed(req)) return send(res, 429, { error: 'rate' });
    const b = await readBody(req);
    const line = state.lines.find(l => l.id === clean(b.lineId, 40) && l.active);
    if (!line) return send(res, 400, { error: 'line' });
    const stopName = cleanName(b.stopName);
    if (stopName.length < 2) return send(res, 400, { error: 'stop' });
    const btime = /^([01]\d|2[0-3]):[0-5]\d$/.test(String(b.time || '').trim()) ? String(b.time).trim() : '';
    if (!btime) return send(res, 400, { error: 'time' });
    const name = cleanName(b.name);
    if (!validName(name)) return send(res, 400, { error: 'name' });
    const company = cleanName(b.company);
    if (!state.companies.includes(company)) return send(res, 400, { error: 'company' });
    const isProf = company === 'بروفيشنال'; // professional riders have no employee code
    const code = isProf ? '' : cleanCode(b.code || '');
    if (!isProf && !validCode(code)) return send(res, 400, { error: 'code' });
    const department = cleanName(b.department);
    if (department.length < 2) return send(res, 400, { error: 'department' });
    const dup = code && state.riders.find(r => r.code === code);
    if (dup) {
      const dl = state.lines.find(l => l.id === dup.lineId);
      return send(res, 409, { error: 'dup', line: dl ? dl.name : '' });
    }
    const rider = { id: uid('R'), lineId: line.id, stopId: '', stopName, time: btime, name, code, company, department, rtype: 'employee', kind: b.kind === 'flex' ? 'flex' : 'fixed', createdAt: new Date().toISOString() };
    state.riders.push(rider); saveSoon();
    return send(res, 200, { ok: true, line: line.name, stop: stopName, time: btime });
  }

  // auth
  if (p === '/api/login' && req.method === 'POST') {
    const b = await readBody(req);
    const uname = clean(b.username, 60).toLowerCase();
    const user = state.users.find(x => String(x.username || '').trim().toLowerCase() === uname);
    if (!user || !verifyPw(b.password || '', user.passHash)) return send(res, 401, { error: 'bad' });
    const t = newSession(user.id);
    return send(res, 200, { ok: true, name: user.username }, { 'Set-Cookie': `sid=${t}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${30 * 24 * 3600}; Secure` });
  }
  if (p === '/api/logout' && req.method === 'POST') {
    const m = /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '');
    if (m) sessions.delete(m[1]);
    return send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; Path=/; HttpOnly; Max-Age=0' });
  }
  if (p === '/api/me') {
    const user = sessionUser(req);
    return send(res, 200, { user: user ? { name: user.username, role: user.role } : null });
  }

  // admin APIs
  const user = sessionUser(req);
  const needAdmin = () => { if (!user) { send(res, 401, { error: 'auth' }); return false; } return true; };

  if (p === '/api/admin/lines') {
    if (!needAdmin()) return;
    const out = state.lines.slice().sort((a, b) => a.position - b.position).map(l => ({
      id: l.id, name: l.name, time: l.time, price: l.price, driver: l.driver, driverId: l.driverId, active: l.active,
      stops: l.stops.map(s => ({ id: s.id, name: s.name })),
      riders: state.riders.filter(r => r.lineId === l.id).map(r => {
        const st = l.stops.find(s => s.id === r.stopId);
        return { id: r.id, name: r.name, code: r.code, company: r.company || '', department: r.department || '', stop: r.stopName || (st ? st.name : ''), stopPos: st ? st.position : 999, kind: r.kind, rtype: r.rtype || 'employee', time: r.time || '', createdAt: r.createdAt };
      }).sort((a, b) => a.stopPos - b.stopPos || a.createdAt.localeCompare(b.createdAt))
    }));
    return send(res, 200, { lines: out, companies: state.companies });
  }

  if (p === '/api/admin/password' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const next = String(b.next || '');
    if (next.length < 6 || next.length > 100) return send(res, 400, { error: 'pwlen' });
    const u = state.users.find(x => x.id === user.id);
    if (!u) return send(res, 400, { error: 'auth' });
    u.passHash = hashPw(next);
    saveSoon();
    return send(res, 200, { ok: true });
  }
  if (p === '/api/admin/companies' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const add = cleanName(b.add), remove = cleanName(b.remove);
    if (add && !state.companies.includes(add)) state.companies.push(add);
    if (remove) state.companies = state.companies.filter(c => c !== remove);
    if (!state.companies.length) state.companies = DEFAULT_COMPANIES.slice();
    saveSoon();
    return send(res, 200, { ok: true, companies: state.companies });
  }

  if (p === '/api/admin/line/toggle' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const l = state.lines.find(x => x.id === clean(b.id, 40));
    if (!l) return send(res, 404, { error: 'nf' });
    l.active = !l.active; saveSoon();
    return send(res, 200, { ok: true, active: l.active });
  }

  if (p === '/api/admin/line/update' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const l = state.lines.find(x => x.id === clean(b.id, 40));
    if (!l) return send(res, 404, { error: 'nf' });
    if (b.name !== undefined) l.name = clean(b.name, 120) || l.name;
    if (b.time !== undefined) l.time = clean(b.time, 20);
    if (b.price !== undefined) l.price = clean(b.price, 20);
    if (b.driver !== undefined) l.driver = clean(b.driver, 120);
    if (b.driverId !== undefined) l.driverId = clean(b.driverId, 40);
    saveSoon();
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/rider/delete' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const i = state.riders.findIndex(r => r.id === clean(b.id, 40));
    if (i < 0) return send(res, 404, { error: 'nf' });
    state.riders.splice(i, 1); saveSoon();
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/rider/update' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const r = state.riders.find(x => x.id === clean(b.id, 40));
    if (!r) return send(res, 404, { error: 'nf' });
    const line = state.lines.find(l => l.id === r.lineId);
    if (b.name !== undefined) r.name = clean(b.name, 120) || r.name;
    if (b.code !== undefined) r.code = clean(b.code, 40) || r.code;
    if (b.company !== undefined) r.company = cleanName(b.company);
    if (b.kind !== undefined) r.kind = b.kind === 'flex' ? 'flex' : 'fixed';
    if (b.stopId !== undefined && line && line.stops.some(s => s.id === b.stopId)) r.stopId = b.stopId;
    if (b.lineId !== undefined) {
      const nl = state.lines.find(l => l.id === clean(b.lineId, 40));
      if (nl) { r.lineId = nl.id; r.stopId = (nl.stops.find(s => s.id === b.stopId) || nl.stops[0]).id; }
    }
    saveSoon();
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/export.xlsx') {
    if (!needAdmin()) return;
    const lineId = u.searchParams.get('line') || '';
    const lines = lineId ? state.lines.filter(l => l.id === lineId) : state.lines.slice().sort((a, b) => a.position - b.position);
    const rows = [['الخط', 'محطة الركوب بالتحديد', 'ميعاد الركوب', 'الاسم', 'الشركة', 'الكود', 'القسم', 'الحاله']];
    for (const l of lines) {
      const riders = state.riders.filter(r => r.lineId === l.id);
      if (!riders.length) { rows.push([l.name, '', '', '', '', '', '', '']); continue; }
      for (const r of riders) {
        const st = l.stops.find(s => s.id === r.stopId);
        rows.push([l.name, r.stopName || (st ? st.name : ''), r.time || '', r.name, r.company || '', r.code || '', r.department || '', r.kind === 'flex' ? 'متغير' : 'ثابت']);
      }
    }
    const buf = buildXlsx(lineId && lines[0] ? lines[0].name : 'كل الخطوط', rows);
    res.writeHead(200, { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Content-Disposition': `attachment; filename="lines.xlsx"` });
    return res.end(buf);
  }

  // PWA icons: PNGs are embedded as base64 in icons-data.js (repo holds text only)
  if (p === '/icon-192.png' || p === '/icon-512.png') {
    const icons = require('./icons-data.js');
    const b64 = icons[p];
    if (b64) {
      res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-cache' });
      return res.end(Buffer.from(b64, 'base64'));
    }
  }

  // Android APK: served from base64 text parts in apk-parts/ (repo holds text only)
  if (p === '/app.apk') {
    try {
      const dir = path.join(__dirname, 'apk-parts');
      const b64 = fs.readdirSync(dir).filter(f => f.endsWith('.txt')).sort().map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('');
      res.writeHead(200, {
        'Content-Type': 'application/vnd.android.package-archive',
        'Content-Disposition': 'attachment; filename="elsewedy-lines.apk"',
        'Cache-Control': 'no-cache'
      });
      return res.end(Buffer.from(b64, 'base64'));
    } catch (e) { return send(res, 404, { error: 'apk-missing' }); }
  }

  // Digital Asset Links: lets the Android TWA open full-screen without the URL bar
  if (p === '/.well-known/assetlinks.json') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    return res.end(JSON.stringify([{
      relation: ['delegate_permission/common.handle_all_urls'],
      target: {
        namespace: 'android_app',
        package_name: 'com.elsewedy.lines',
        sha256_cert_fingerprints: ['F3:7E:AC:9C:0A:AD:8D:A2:DD:4A:37:8F:8C:20:AF:EE:53:06:E2:1C:BE:5F:B8:86:79:26:ED:63:7A:9B:AE:91']
      }
    }]));
  }

  // static
  let fp = p === '/' ? '/index.html' : p;
  const file = path.join(__dirname, 'public', path.normalize(fp).replace(/^(\.\.[/\\])+/, ''));
  if (file.startsWith(path.join(__dirname, 'public')) && fs.existsSync(file) && fs.statSync(file).isFile()) {
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    return fs.createReadStream(file).pipe(res);
  }
  send(res, 404, { error: 'nf' });
}

/* ---------------- boot ---------------- */
(async () => {
  try { await initPg(); } catch (e) { console.error('PG init failed, falling back to file:', e.message); pgPool = null; }
  state = await loadState();
  if (!state || !Array.isArray(state.lines)) { state = seedState(); await saveNow(); console.log('seeded', state.lines.length, 'lines'); }
  if (!Array.isArray(state.companies) || !state.companies.length) { state.companies = DEFAULT_COMPANIES.slice(); saveSoon(); }
  ensureAdmin();
  http.createServer((req, res) => handle(req, res).catch(e => { console.error(e); try { send(res, 500, { error: 'srv' }); } catch (_) {} }))
    .listen(PORT, () => console.log('listening on', PORT, pgPool ? '(postgres)' : '(file)'));
})();
