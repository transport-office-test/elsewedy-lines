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
function makeSheetXml(rows, opts) {
  // rows: array of arrays of strings; opts: { widths: [..], centerCols: [colIndex, ..] }
  const widths = (opts && opts.widths) || [];
  const centerCols = (opts && opts.centerCols) || [];
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const estLines = (c, w) => {
    const s = String(c == null ? '' : c);
    if (!s) return 1;
    const per = Math.max(4, Math.floor((w || 12) - 2));
    let len = 0;
    for (const ch of s) len += /[0-9a-zA-Z .:'\-]/.test(ch) ? 1 : 1.15;
    return Math.max(1, Math.ceil(len / per));
  };
  let sheetRows = '';
  rows.forEach((r, ri) => {
    const isHead = ri === 0;
    const lines = isHead ? 1 : Math.max.apply(null, r.map((c, ci) => estLines(c, widths[ci])));
    const htAttr = isHead ? ' ht="32" customHeight="1"' : (lines > 1 ? ` ht="${Math.round(lines * 14.5 + 4)}" customHeight="1"` : '');
    sheetRows += `<row r="${ri + 1}"${htAttr}>` + r.map((c, ci) => {
      const ref = String.fromCharCode(65 + ci) + (ri + 1);
      const st = isHead ? 1 : (centerCols.indexOf(ci) !== -1 ? 3 : 2);
      return `<c r="${ref}" s="${st}" t="inlineStr"><is><t>${esc(c)}</t></is></c>`;
    }).join('') + '</row>';
  });
  const colsXml = widths.length ? `<cols>${widths.map((w, i) => `<col min="${i + 1}" max="${i + 1}" width="${w}" customWidth="1"/>`).join('')}</cols>` : '';
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView rightToLeft="1" showGridLines="1" workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>${colsXml}<sheetData>${sheetRows}</sheetData></worksheet>`;
}

function buildXlsxMulti(sheets) {
  // sheets: [{ name, rows, opts }] -> one workbook, one worksheet per entry
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF12204A"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left style="thin"><color rgb="FFB0B7C3"/></left><right style="thin"><color rgb="FFB0B7C3"/></right><top style="thin"><color rgb="FFB0B7C3"/></top><bottom style="thin"><color rgb="FFB0B7C3"/></bottom><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`;
  const wbXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s, i) => `<sheet name="${esc(s.name).slice(0, 31)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`;
  const relsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((s, i) => `<Relationship Id="rId${i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i + 1}.xml"/>`).join('')}<Relationship Id="rId${sheets.length + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`;
  const rootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const ctXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>${sheets.map((s, i) => `<Override PartName="/xl/worksheets/sheet${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`).join('')}<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>`;
  const files = [
    ['[Content_Types].xml', ctXml], ['_rels/.rels', rootRels],
    ['xl/workbook.xml', wbXml], ['xl/_rels/workbook.xml.rels', relsXml],
    ...sheets.map((s, i) => [`xl/worksheets/sheet${i + 1}.xml`, makeSheetXml(s.rows, s.opts)]),
    ['xl/styles.xml', stylesXml]
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

function buildXlsx(sheetName, rows, opts) { return buildXlsxMulti([{ name: sheetName, rows, opts }]); }

/* ---------------- time: free text allowed (hour-only like "1" or "الساعة 1") ---------------- */
function cleanTimeText(v) {
  let x = String(v == null ? '' : v).replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x660)).replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x6F0));
  return x.replace(/\s+/g, ' ').trim().slice(0, 20);
}
function timeSortKey(v) {
  const x = cleanTimeText(v);
  const m = x.match(/^([01]?\d|2[0-3]):([0-5]\d)/);
  if (m) return String(+m[1] * 60 + +m[2]).padStart(4, '0');
  const hh = x.match(/(?:^|\D)([01]?\d|2[0-3])(?:\D|$)/);
  if (hh) return String(+hh[1] * 60).padStart(4, '0');
  return '9999'; // unparseable free text sorts last
}

/* ---------------- admin activity log ---------------- */
function normStopKey(v) {
  return String(v == null ? '' : v)
    .replace(/[\u064B-\u0652\u0670\u0640]/g, '') // Arabic diacritics + dagger alef + tatweel
    .replace(/[\u0623\u0625\u0622\u0671]/g, '\u0627') // alef variants -> alef
    .replace(/\u0629/g, '\u0647') // teh marbuta -> heh
    .replace(/\u0649/g, '\u064A') // alef maqsura -> yeh
    .replace(/\s+/g, ' ').trim().toLowerCase();
}

// add an employee-typed station to a line if it is not already there (normalised dedupe)
function ensureStop(line, stopName) {
  const key = normStopKey(stopName);
  if (!key || !line) return;
  if (line.stops.some(st => normStopKey(st.name) === key)) return;
  const pos = line.stops.reduce((m, st) => Math.max(m, st.position || 0), -1) + 1;
  line.stops.push({ id: uid('S'), name: stopName, position: pos });
  logAction('\u0625\u0636\u0627\u0641\u0629 \u0645\u063D\u0637\u0629', { name: '', code: '', lineId: line.id }, stopName);
}

function logAction(action, r, details) {
  if (!Array.isArray(state.log)) state.log = [];
  const lineName = (state.lines.find(l => l.id === r.lineId) || {}).name || '';
  state.log.push({ id: uid('G'), at: new Date().toISOString(), action, riderName: r.name || '', code: r.code || '', line: lineName, details: details || '' });
  if (state.log.length > 500) state.log.splice(0, state.log.length - 500);
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
    const btime = cleanTimeText(b.time);
    if (!btime) return send(res, 400, { error: 'time' });
    const name = cleanName(b.name);
    if (!validName(name)) return send(res, 400, { error: 'name' });
    const company = cleanName(b.company);
    if (!state.companies.includes(company)) return send(res, 400, { error: 'company' });
    const isProf = company === 'بروفيشنال'; // professional riders have no employee code; they write the company they work for instead
    const code = isProf ? cleanName(b.code || '') : cleanCode(b.code || '');
    if (!isProf && !validCode(code)) return send(res, 400, { error: 'code' });
    if (isProf && code.length < 2) return send(res, 400, { error: 'code' });
    const department = cleanName(b.department);
    if (department.length < 2) return send(res, 400, { error: 'department' });
    const kind = b.kind === 'flex' ? 'flex' : 'fixed';
    let line2Name = '', line2Id = '', stop2 = '', btime2 = '', line3Name = '', line3Id = '', stop3 = '', btime3 = '';
    let l2 = null, l3 = null;
    if (kind === 'flex') {
      l2 = state.lines.find(l => l.id === clean(b.line2Id, 40) && l.active);
      if (!l2) return send(res, 400, { error: 'line2' });
      line2Id = l2.id; line2Name = l2.name;
      stop2 = cleanName(b.stop2);
      if (stop2.length < 2) return send(res, 400, { error: 'stop2' });
      btime2 = cleanTimeText(b.time2);
      if (!btime2) return send(res, 400, { error: 'time2' });
      l3 = state.lines.find(l => l.id === clean(b.line3Id, 40) && l.active);
      if (!l3) return send(res, 400, { error: 'line3' });
      line3Id = l3.id; line3Name = l3.name;
      stop3 = cleanName(b.stop3);
      if (stop3.length < 2) return send(res, 400, { error: 'stop3' });
      btime3 = cleanTimeText(b.time3);
      if (!btime3) return send(res, 400, { error: 'time3' });
    }
    const dup = code && !isProf && state.riders.find(r => !r.deletedAt && r.code === code && r.company !== 'بروفيشنال');
    if (dup) {
      const dl = state.lines.find(l => l.id === dup.lineId);
      return send(res, 409, { error: 'dup', line: dl ? dl.name : '' });
    }
    const rider = { id: uid('R'), lineId: line.id, stopId: '', stopName, time: btime, name, code, company, department, rtype: 'employee', kind, line2Id, stop2, time2: btime2, line3Id, stop3, time3: btime3, createdAt: new Date().toISOString() };
    ensureStop(line, stopName);
    if (l2) ensureStop(l2, stop2);
    if (l3) ensureStop(l3, stop3);
    state.riders.push(rider); saveSoon();
    return send(res, 200, { ok: true, line: line.name, stop: stopName, time: btime, line2: line2Name, stop2, time2: btime2, line3: line3Name, stop3, time3: btime3 });
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
      id: l.id, name: l.name, time: l.time, price: l.price, driver: l.driver, driverId: l.driverId, active: l.active, capacity: l.capacity || 0,
      stops: l.stops.map(s => ({ id: s.id, name: s.name })),
      riders: state.riders.filter(r => !r.deletedAt && r.lineId === l.id).map(r => {
        const st = l.stops.find(s => s.id === r.stopId);
        const l2n = (state.lines.find(x => x.id === r.line2Id) || {}).name || '';
        const l3n = (state.lines.find(x => x.id === r.line3Id) || {}).name || '';
        return { id: r.id, name: r.name, code: r.code, company: r.company || '', department: r.department || '', stop: r.stopName || (st ? st.name : ''), stopPos: st ? st.position : 999, kind: r.kind, rtype: r.rtype || 'employee', time: r.time || '', line2: l2n, stop2: r.stop2 || '', time2: r.time2 || '', line3: l3n, stop3: r.stop3 || '', time3: r.time3 || '', createdAt: r.createdAt };
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

  if (p === '/api/admin/line/add' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const name = clean(b.name, 120);
    if (name.length < 2) return send(res, 400, { error: 'name' });
    if (state.lines.some(l => String(l.name).trim() === name)) return send(res, 409, { error: 'dup' });
    const stops = (Array.isArray(b.stops) ? b.stops : []).map(x => cleanName(x)).filter(x => x.length >= 2).slice(0, 60);
    const pos = state.lines.reduce((m, l) => Math.max(m, l.position || 0), -1) + 1;
    const line = { id: uid('L'), name, time: '', price: '', driver: '', driverId: '', active: true, position: pos, capacity: 0, stops: stops.map((sn, j) => ({ id: uid('S'), name: sn, position: j })) };
    state.lines.push(line); saveSoon();
    logAction('إضافة خط', { name: '', code: '', lineId: line.id }, stops.length + ' محطة');
    return send(res, 200, { ok: true, id: line.id });
  }

  if (p === '/api/admin/line/delete' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const lid = clean(b.id, 40);
    const i = state.lines.findIndex(x => x.id === lid);
    if (i < 0) return send(res, 404, { error: 'nf' });
    if (state.riders.some(r => r.lineId === lid || r.line2Id === lid || r.line3Id === lid)) return send(res, 400, { error: 'hasriders' });
    logAction('حذف خط', { name: '', code: '', lineId: lid }, '');
    state.lines.splice(i, 1); saveSoon();
    return send(res, 200, { ok: true });
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
    if (b.capacity !== undefined) { const c = parseInt(String(b.capacity).replace(/[^0-9]/g, ''), 10); l.capacity = (Number.isFinite(c) && c > 0 && c <= 500) ? c : 0; }
    saveSoon();
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/rider/delete' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const r = state.riders.find(x => x.id === clean(b.id, 40));
    if (!r || r.deletedAt) return send(res, 404, { error: 'nf' });
    r.deletedAt = new Date().toISOString(); saveSoon();
    logAction('حذف', r, '');
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/rider/restore' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const r = state.riders.find(x => x.id === clean(b.id, 40));
    if (!r || !r.deletedAt) return send(res, 404, { error: 'nf' });
    delete r.deletedAt; saveSoon();
    logAction('استرجاع', r, '');
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/rider/purge' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const i = state.riders.findIndex(x => x.id === clean(b.id, 40));
    if (i < 0 || !state.riders[i].deletedAt) return send(res, 404, { error: 'nf' });
    logAction('حذف نهائي', state.riders[i], '');
    state.riders.splice(i, 1); saveSoon();
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/trash') {
    if (!needAdmin()) return;
    const items = state.riders.filter(r => r.deletedAt).map(r => ({
      id: r.id, name: r.name, code: r.code || '', company: r.company || '', department: r.department || '',
      stop: r.stopName || '', time: r.time || '', kind: r.kind || 'fixed',
      line: (state.lines.find(l => l.id === r.lineId) || {}).name || '', deletedAt: r.deletedAt
    })).sort((a, b) => String(b.deletedAt).localeCompare(String(a.deletedAt)));
    return send(res, 200, { items });
  }

  if (p === '/api/admin/log') {
    if (!needAdmin()) return;
    const items = (state.log || []).slice().sort((a, b) => String(b.at).localeCompare(String(a.at))).slice(0, 200);
    return send(res, 200, { items });
  }

  if (p === '/api/admin/log.csv') {
    if (!needAdmin()) return;
    const items = (state.log || []).slice().sort((a, b) => String(b.at).localeCompare(String(a.at)));
    const q = v => '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"';
    const rows = [['الوقت', 'العملية', 'الاسم', 'الكود', 'الخط', 'التفاصيل'].map(q).join(',')];
    for (const e of items) rows.push([e.at, e.action, e.riderName, e.code, e.line, e.details].map(q).join(','));
    res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="log.csv"' });
    return res.end('\ufeff' + rows.join('\r\n'));
  }

  if (p === '/api/admin/rider/update' && req.method === 'POST') {
    if (!needAdmin()) return;
    const b = await readBody(req);
    const r = state.riders.find(x => x.id === clean(b.id, 40));
    if (!r) return send(res, 404, { error: 'nf' });
    const before = { name: r.name, code: r.code, company: r.company, department: r.department, stopName: r.stopName, time: r.time, kind: r.kind, stop2: r.stop2, time2: r.time2, stop3: r.stop3, time3: r.time3, lineId: r.lineId };
    const line = state.lines.find(l => l.id === r.lineId);
    if (b.name !== undefined) r.name = clean(b.name, 120) || r.name;
    if (b.code !== undefined) r.code = clean(b.code, 40) || r.code;
    if (b.company !== undefined) r.company = cleanName(b.company);
    if (b.department !== undefined) r.department = cleanName(b.department);
    if (b.stopName !== undefined) { const s = cleanName(b.stopName); if (s.length >= 2) { r.stopName = s; r.stopId = ''; } }
    if (b.time !== undefined) { const tv = cleanTimeText(b.time); if (tv) r.time = tv; }
    if (b.kind !== undefined) r.kind = b.kind === 'flex' ? 'flex' : 'fixed';
    if (b.stop2 !== undefined) r.stop2 = cleanName(b.stop2);
    if (b.time2 !== undefined) { const tv2 = cleanTimeText(b.time2); if (tv2) r.time2 = tv2; }
    if (b.stop3 !== undefined) r.stop3 = cleanName(b.stop3);
    if (b.time3 !== undefined) { const tv3 = cleanTimeText(b.time3); if (tv3) r.time3 = tv3; }
    if (b.stopId !== undefined && line && line.stops.some(s => s.id === b.stopId)) r.stopId = b.stopId;
    if (b.lineId !== undefined) {
      const nl = state.lines.find(l => l.id === clean(b.lineId, 40));
      if (nl) { r.lineId = nl.id; r.stopId = ((nl.stops.find(s => s.id === b.stopId) || nl.stops[0]) || {}).id || ''; r.stopName = ''; }
    }
    const labels = { name: 'الاسم', code: 'الكود', company: 'الشركة', department: 'القسم', stopName: 'المحطة', time: 'الميعاد', kind: 'الحالة', stop2: 'محطة الوردية التانية', time2: 'ميعاد الوردية التانية', stop3: 'محطة الوردية التالتة', time3: 'ميعاد الوردية التالتة', lineId: 'الخط' };
    const changes = [];
    for (const k of Object.keys(labels)) {
      const fmt = (k2, v) => k2 === 'lineId' ? ((state.lines.find(l2 => l2.id === v) || {}).name || '') : k2 === 'kind' ? (v === 'flex' ? 'متغير' : 'ثابت') : String(v == null ? '' : v);
      const ov = fmt(k, before[k]), nv = fmt(k, r[k]);
      if (ov !== nv) changes.push(labels[k] + ': «' + ov + '» ← «' + nv + '»');
    }
    if (changes.length) logAction('تعديل', r, changes.join(' • '));
    saveSoon();
    return send(res, 200, { ok: true });
  }

  // print-ready A4 sheet for one line (admin only): riders sorted by boarding time, fixed before flex at equal times
  if (p === '/api/admin/line/sheet') {
    if (!needAdmin()) return;
    const l = state.lines.find(x => x.id === clean(u.searchParams.get('id') || '', 40));
    if (!l) return send(res, 404, { error: 'nf' });
    const escH = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const lineName = x => (state.lines.find(y => y.id === x) || {}).name || '';
    const riders = state.riders.filter(r => !r.deletedAt && r.lineId === l.id).slice()
      .sort((a, b) => timeSortKey(a.time).localeCompare(timeSortKey(b.time)) || (a.kind === b.kind ? 0 : a.kind === 'flex' ? 1 : -1) || String(a.createdAt).localeCompare(String(b.createdAt)));
    const rowsHtml = riders.map((r, i) => {
      const st = l.stops.find(s => s.id === r.stopId);
      const shifts = r.kind === 'flex'
        ? `<div class="sh">الوردية التانية: ${escH(lineName(r.line2Id))} • ${escH(r.stop2 || '')} • ${escH((r.time2 || ''))}</div><div class="sh">الوردية التالتة: ${escH(lineName(r.line3Id))} • ${escH(r.stop3 || '')} • ${escH((r.time3 || ''))}</div>`
        : '';
      return `<tr><td>${i + 1}</td><td class="nm">${escH(r.name)}${shifts}</td><td>${escH(r.code) || '—'}</td><td>${escH(r.company || '')}</td><td>${escH(r.department || '')}</td><td>${escH(r.stopName || (st ? st.name : ''))}</td><td>${escH((r.time || ''))}</td><td>${r.kind === 'flex' ? 'متغير' : 'ثابت'}</td></tr>`;
    }).join('');
    const html = `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>كشف خط ${escH(l.name)}</title><style>*{box-sizing:border-box;margin:0}body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;color:#111;padding:24px;max-width:800px;margin:0 auto}.head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:6px}h1{font-size:20px}.mut{color:#555;font-size:12.5px;margin-bottom:14px}table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:13px}col.c-m{width:5%}col.c-name{width:27%}col.c-code{width:11%}col.c-comp{width:12%}col.c-dept{width:13%}col.c-stop{width:17%}col.c-time{width:8%}col.c-kind{width:7%}th,td{border:1px solid #999;padding:7px 8px;text-align:right;vertical-align:top;overflow-wrap:break-word}th{background:#eee;font-weight:700;-webkit-print-color-adjust:exact;print-color-adjust:exact}td.nm{font-weight:700}tr{break-inside:avoid;page-break-inside:avoid}thead{display:table-header-group}.sh{font-weight:400;font-size:11.5px;color:#333;margin-top:3px}.btn-print{padding:8px 18px;border:0;border-radius:8px;background:#1b2a4a;color:#fff;font-weight:700;cursor:pointer;font-size:14px}@page{size:A4;margin:12mm}@media print{.btn-print{display:none}body{padding:0;max-width:none}}</style></head><body><div class="head"><h1>كشف ركوب خط: ${escH(l.name)}</h1><button class="btn-print" onclick="window.print()">طباعة</button></div><div class="mut">${riders.length} موظف • مرتب بميعاد الركوب • خطوط سير العربيات — السويدي إيجيتك</div><table><colgroup><col class="c-m"><col class="c-name"><col class="c-code"><col class="c-comp"><col class="c-dept"><col class="c-stop"><col class="c-time"><col class="c-kind"></colgroup><thead><tr><th>م</th><th>الاسم</th><th>الكود</th><th>الشركة</th><th>القسم</th><th>محطة الركوب</th><th>الميعاد</th><th>الحالة</th></tr></thead><tbody>${rowsHtml}</tbody></table></body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    return res.end(html);
  }

  if (p === '/api/admin/export.xlsx') {
    if (!needAdmin()) return;
    const lineId = u.searchParams.get('line') || '';
    const flat = u.searchParams.get('flat') === '1';
    const lines = lineId ? state.lines.filter(l => l.id === lineId) : state.lines.slice().sort((a, b) => a.position - b.position);
    const head = ['الخط', 'محطة الركوب بالتحديد', 'ميعاد الركوب', 'الاسم', 'الشركة', 'الكود', 'القسم', 'الحاله', 'خط الوردية التانية', 'محطة الوردية التانية', 'ميعاد الوردية التانية', 'خط الوردية التالتة', 'محطة الوردية التالتة', 'ميعاد الوردية التالتة'];
    const riderCells = (l, r) => {
      const st = l.stops.find(s => s.id === r.stopId);
      const l2n = (state.lines.find(x => x.id === r.line2Id) || {}).name || '';
      const l3n = (state.lines.find(x => x.id === r.line3Id) || {}).name || '';
      return [r.stopName || (st ? st.name : ''), r.time || '', r.name, r.company || '', r.code || '', r.department || '', r.kind === 'flex' ? 'متغير' : 'ثابت', l2n, r.stop2 || '', r.time2 || '', l3n, r.stop3 || '', r.time3 || ''];
    };
    let buf;
    if (lineId || flat) {
      // single flat sheet (per-line button, or ?flat=1 used by the daily backup)
      const rows = [head];
      for (const l of lines) {
        const riders = state.riders.filter(r => !r.deletedAt && r.lineId === l.id);
        if (!riders.length) { rows.push([l.name, '', '', '', '', '', '', '', '', '', '', '', '', '', '']); continue; }
        for (const r of riders) rows.push([l.name, ...riderCells(l, r)]);
      }
      buf = buildXlsx(lineId && lines[0] ? lines[0].name : 'كل الخطوط', rows, { widths: [26, 22, 10, 20, 14, 8, 14, 8, 22, 18, 12, 22, 18, 12], centerCols: [2, 5, 7, 10, 13] });
    } else {
      // one workbook: summary sheet + one sheet per line, riders sorted by boarding time
      const byTime = l => state.riders.filter(r => !r.deletedAt && r.lineId === l.id).slice().sort((x, y) => timeSortKey(x.time).localeCompare(timeSortKey(y.time)) || String(x.createdAt).localeCompare(String(y.createdAt)));
      const summary = [['الخط', 'عدد الموظفين']];
      let total = 0;
      for (const l of lines) { const n = state.riders.filter(r => !r.deletedAt && r.lineId === l.id).length; total += n; summary.push([l.name, String(n)]); }
      summary.push(['الإجمالي', String(total)]);
      const sheets = [{ name: 'كل الخطوط', rows: summary, opts: { widths: [30, 12], centerCols: [1] } }];
      const used = new Set();
      for (const l of lines) {
        let nm = (l.name || 'خط').replace(/[\\\/\?\*\[\]:]/g, ' ').slice(0, 31) || 'خط';
        const base = nm; let k = 2;
        while (used.has(nm)) nm = (base.slice(0, 27) + ' ' + k++).slice(0, 31);
        used.add(nm);
        const rows = [head.slice(1)];
        for (const r of byTime(l)) rows.push(riderCells(l, r));
        sheets.push({ name: nm, rows, opts: { widths: [22, 10, 20, 14, 8, 14, 8, 22, 18, 12, 22, 18, 12], centerCols: [1, 4, 6, 9, 12] } });
      }
      buf = buildXlsxMulti(sheets);
    }
    res.writeHead(200, { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Content-Disposition': `attachment; filename="lines.xlsx"` });
    return res.end(buf);
  }

  // PWA icons: PNGs are embedded as base64 in icons-data.js (repo holds text only)
  if (p === '/icon-192.png' || p === '/icon-512.png' || p === '/og-image.jpg') {
    const icons = require('./icons-data.js');
    const b64 = icons[p];
    if (b64) {
      const ct = p.endsWith('.jpg') ? 'image/jpeg' : 'image/png';
      res.writeHead(200, { 'Content-Type': ct, 'Cache-Control': 'no-cache' });
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
  if (!Array.isArray(state.log)) { state.log = []; saveSoon(); }
  ensureAdmin();
  http.createServer((req, res) => handle(req, res).catch(e => { console.error(e); try { send(res, 500, { error: 'srv' }); } catch (_) {} }))
    .listen(PORT, () => console.log('listening on', PORT, pgPool ? '(postgres)' : '(file)'));
})();
