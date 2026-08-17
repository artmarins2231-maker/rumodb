/**
 * RumoDB — servidor local (Node puro, sem dependências externas)
 * ------------------------------------------------------------------
 * - Senhas: hash PBKDF2 (100k iterações, SHA-256) com salt único por usuário.
 *   Nada de senha em texto puro é gravado em disco, nem o hash bruto é
 *   devolvido ao navegador.
 * - Sessões: token aleatório (256 bits) guardado em memória, expira em 7 dias.
 * - Painel admin (/api/admin/*): exige o cabeçalho X-Admin-Key com a chave
 *   gerada automaticamente no primeiro boot (arquivo admin.key, local e
 *   fora do site). Sem essa chave não dá pra listar usuários nem apagar o banco.
 * - Rate limit simples por IP nas rotas de login/cadastro (anti força-bruta).
 * - Escrita atômica no rumodb.json (evita corromper o arquivo se o processo
 *   cair no meio de uma gravação).
 * - CORS restrito: só reflete Origin de localhost/127.0.0.1 (uso em dev).
 *   Em produção, sirva o front pelo mesmo servidor/origem e não precisa de CORS.
 */
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;

// ---------- .env simples (sem dependências) ----------
// Carrega ROOT/.env se existir: linhas "CHAVE=valor", # é comentário.
// Não sobrescreve variáveis já definidas no ambiente (systemd, docker, etc.).
(function loadEnv() {
  const envPath = path.join(ROOT, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const l = line.trim();
    if (!l || l.startsWith('#')) continue;
    const eq = l.indexOf('=');
    if (eq === -1) continue;
    const key = l.slice(0, eq).trim();
    let val = l.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
})();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const SITE_URL = process.env.SITE_URL || ''; // ex: https://www.seudominio.com.br
// ---------- AURORA (IA real, opcional) ----------
// Se ANTHROPIC_API_KEY estiver definida no .env, a AURORA passa a responder
// com um modelo de verdade (via API da Anthropic) em vez do modo local
// baseado em regras. Sem a chave, o site continua funcionando normalmente
// no modo local (nada quebra e nenhuma chamada externa é feita).
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const AI_MODEL = process.env.AI_MODEL || 'claude-sonnet-5';
const DB_FILE = path.join(ROOT, 'rumodb.json');
const ADMIN_KEY_FILE = path.join(ROOT, 'admin.key');
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 dias
const PBKDF2_ITER = 100000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // sem 0/O/1/I/L, evita confusão

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp'
};

// Arquivos que NUNCA podem ser servidos como estático, mesmo que alguém
// adivinhe o nome (evita vazar o banco ou a chave admin pela web).
const FORBIDDEN_STATIC = new Set(['rumodb.json', 'admin.key', 'server.js', 'iniciar.bat', '.env', 'package.json', 'package-lock.json']);

// ---------- utilidades de arquivo ----------
function atomicWrite(file, data) {
  const tmp = file + '.tmp-' + crypto.randomBytes(4).toString('hex');
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function loadDB() {
  try {
    const raw = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    return {
      users: Array.isArray(raw.users) ? raw.users : [],
      logins: Array.isArray(raw.logins) ? raw.logins : [],
      codes: Array.isArray(raw.codes) ? raw.codes : [],
      seq: Number(raw.seq) || 1
    };
  } catch (e) {
    return { users: [], logins: [], codes: [], seq: 1 };
  }
}
function saveDB(db) { atomicWrite(DB_FILE, JSON.stringify(db, null, 2)); }

// Tamanho mínimo aceitável pra uma chave admin (chaves geradas aqui têm ~32
// caracteres). Se o arquivo existir mas for mais curto que isso — por ex.
// alguém trocou à mão por algo fraco tipo "8827vghs15" — a gente troca por
// uma nova chave forte automaticamente, pra não deixar o painel admin
// vulnerável a força bruta.
const MIN_ADMIN_KEY_LEN = 24;
function getOrCreateAdminKey() {
  try {
    const existing = fs.readFileSync(ADMIN_KEY_FILE, 'utf8').trim();
    if (existing && existing.length >= MIN_ADMIN_KEY_LEN) return existing;
    if (existing) {
      console.log('');
      console.log('⚠️  admin.key encontrado é FRACO (curto demais) — gerando uma chave nova e forte automaticamente.');
    }
  } catch (e) { /* ainda não existe */ }
  const key = crypto.randomBytes(24).toString('base64url');
  atomicWrite(ADMIN_KEY_FILE, key + '\n');
  console.log('');
  console.log('🔑 Chave admin criada (guarde em local seguro, não é mostrada de novo aqui):');
  console.log('   ' + key);
  console.log('   Também salva em: ' + ADMIN_KEY_FILE);
  console.log('');
  return key;
}
const ADMIN_KEY = getOrCreateAdminKey();

// ---------- senha ----------
function hashPassword(senha, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(senha, s, PBKDF2_ITER, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
  return { hash, salt: s };
}
function verifyPassword(senha, salt, hash) {
  const test = crypto.pbkdf2Sync(senha, salt, PBKDF2_ITER, PBKDF2_KEYLEN, PBKDF2_DIGEST).toString('hex');
  const a = Buffer.from(test, 'hex'), b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- sessões (em memória) ----------
const sessions = new Map(); // token -> { email, exp }
function createSession(email) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(token, { email, exp: Date.now() + SESSION_TTL_MS });
  return token;
}
function sessionEmail(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.exp) { sessions.delete(token); return null; }
  return s.email;
}
function bearerToken(req) {
  const h = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1] : null;
}
setInterval(() => { for (const [tok, s] of sessions) if (Date.now() > s.exp) sessions.delete(tok); }, 60 * 60 * 1000).unref();

// ---------- rate limit simples por IP ----------
const buckets = new Map(); // key(ip+rota) -> {count, resetAt}
function rateLimited(key, max, windowMs) {
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now > b.resetAt) { b = { count: 0, resetAt: now + windowMs }; buckets.set(key, b); }
  b.count++;
  return b.count > max;
}
function clientIp(req) {
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

// ---------- validação ----------
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
function publicUser(u) {
  return {
    id: u.id, nome: u.nome, email: u.email, cidade: u.cidade || '',
    criado_em: u.criado_em, ultima_entrada: u.ultima_entrada,
    premium: !!u.premium, premium_desde: u.premium_desde || null
  };
}
function adminUser(u) {
  // Painel admin: nunca devolve o hash nem o salt inteiros, só uma prévia.
  return { ...publicUser(u), hash_preview: (u.hash || '').slice(0, 10) + '…' };
}
function genCode() {
  let s = '';
  for (let i = 0; i < 12; i++) {
    if (i > 0 && i % 4 === 0) s += '-';
    s += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  }
  return 'RUMO-' + s;
}

// ---------- AURORA — chamada ao modelo real (Anthropic) ----------
async function callAnthropic(messages, system) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({ model: AI_MODEL, max_tokens: 500, system, messages })
  });
  if (!r.ok) {
    const errBody = await r.text().catch(() => '');
    throw new Error('anthropic_http_' + r.status + ': ' + errBody.slice(0, 300));
  }
  const data = await r.json();
  const text = (data.content || []).filter(b => b.type === 'text').map(b => b.text).join('\n').trim();
  return text;
}
const LANG_NAMES = { pt: 'português do Brasil', en: 'English', es: 'español' };
function buildAuroraSystem(lang, context) {
  const langName = LANG_NAMES[lang] || LANG_NAMES.pt;
  return [
    `Você é AURORA, a copiloto de viagens do site Rumo. Responda sempre em ${langName}, com tom simpático, direto e curto (no máximo 3–4 frases).`,
    'Pode usar **negrito** e quebras de linha, mas não use listas markdown nem títulos.',
    'Baseie-se SOMENTE nos dados de contexto abaixo (já calculados pelo site: orçamento, dias, destinos e preços) — nunca invente preços, nomes de hotéis, companhias ou destinos que não estejam no contexto.',
    'Se o contexto não tiver orçamento nem destinos, peça de forma breve a informação que falta (ex.: quanto a pessoa tem pra gastar e quantos dias).',
    'Fale só sobre viagens e sobre o próprio site Rumo; se perguntarem qualquer outra coisa, recuse com bom humor e traga o assunto de volta pra viagem.',
    'Contexto atual (JSON): ' + JSON.stringify(context || {})
  ].join(' ');
}

// ---------- HTTP helpers ----------
function cors(req, res) {
  const origin = req.headers.origin;
  if (origin && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
}
function securityHeaders(res, req) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
  // CSP: permite as fontes do Google Fonts usadas no index.html e a API do
  // Open-Meteo (clima). 'unsafe-inline' no style/script é necessário porque
  // o site é um único HTML com <style>/<script> inline — se algum dia isso
  // migrar pra arquivos externos, dá pra apertar essa política.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self' https://api.open-meteo.com https://geocoding-api.open-meteo.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; '));
  // HSTS só faz sentido em HTTPS — em dev local (http://localhost) o header
  // é inofensivo mas fica sem efeito; ative de verdade quando o site estiver
  // atrás de um domínio com certificado.
  const isHttps = NODE_ENV === 'production' && (req && (req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted));
  if (isHttps) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
}
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readBody(req, limit = 2e6) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > limit) { req.destroy(); reject(new Error('payload too large')); return; }
      data += c;
    });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}
async function readJSON(req) {
  const raw = await readBody(req);
  if (!raw) return {};
  return JSON.parse(raw);
}
// Rate limit dedicado pras rotas admin: independe de estar certo ou errado,
// limita tentativas por IP pra dificultar força bruta da chave.
function requireAdmin(req) {
  const ip = clientIp(req);
  if (rateLimited('admin:' + ip, 30, 60_000)) return false;
  const key = req.headers['x-admin-key'];
  return typeof key === 'string' && key.length > 0 &&
    key.length === ADMIN_KEY.length && crypto.timingSafeEqual(Buffer.from(key), Buffer.from(ADMIN_KEY));
}

// ---------- rotas ----------
async function handleApi(req, res, p) {
  if (p === '/api/ping' && req.method === 'GET') return send(res, 200, { ok: true, ts: Date.now() });

  // cadastro
  if (p === '/api/signup' && req.method === 'POST') {
    if (rateLimited('signup:' + clientIp(req), 8, 60_000)) return send(res, 429, { ok: false, error: 'rate_limited' });
    let body;
    try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const nome = String(body.nome || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const senha = String(body.senha || '');
    const cidade = String(body.cidade || '').trim();
    if (nome.length < 2 || nome.length > 80) return send(res, 400, { ok: false, error: 'nome' });
    if (!EMAIL_RE.test(email) || email.length > 200) return send(res, 400, { ok: false, error: 'email' });
    if (!cidade || cidade.length > 80) return send(res, 400, { ok: false, error: 'cidade' });
    if (senha.length < 6 || senha.length > 200) return send(res, 400, { ok: false, error: 'senha' });

    const db = loadDB();
    if (db.users.find(u => u.email === email)) return send(res, 409, { ok: false, error: 'exists' });
    const { hash, salt } = hashPassword(senha);
    const now = new Date().toISOString();
    const user = { id: db.seq++, nome, email, cidade, hash, salt, criado_em: now, ultima_entrada: now };
    db.users.push(user);
    db.logins = [...db.logins, { email, em: now }].slice(-50);
    saveDB(db);
    const token = createSession(email);
    return send(res, 201, { ok: true, token, user: publicUser(user) });
  }

  // login
  if (p === '/api/login' && req.method === 'POST') {
    if (rateLimited('login:' + clientIp(req), 12, 60_000)) return send(res, 429, { ok: false, error: 'rate_limited' });
    let body;
    try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const email = String(body.email || '').trim().toLowerCase();
    const senha = String(body.senha || '');
    const db = loadDB();
    const user = db.users.find(u => u.email === email);
    // Mesma resposta pra "não existe" e "senha errada" — não vaza quais e-mails têm conta.
    if (!user || !verifyPassword(senha, user.salt, user.hash)) {
      return send(res, 401, { ok: false, error: 'creds' });
    }
    user.ultima_entrada = new Date().toISOString();
    db.logins = [...db.logins, { email, em: user.ultima_entrada }].slice(-50);
    saveDB(db);
    const token = createSession(email);
    return send(res, 200, { ok: true, token, user: publicUser(user) });
  }

  // sessão atual
  if (p === '/api/me' && req.method === 'GET') {
    const email = sessionEmail(bearerToken(req));
    if (!email) return send(res, 401, { ok: false, error: 'no_session' });
    const db = loadDB();
    const user = db.users.find(u => u.email === email);
    if (!user) return send(res, 401, { ok: false, error: 'no_session' });
    return send(res, 200, { ok: true, user: publicUser(user) });
  }

  // logout
  if (p === '/api/logout' && req.method === 'POST') {
    const tok = bearerToken(req);
    if (tok) sessions.delete(tok);
    return send(res, 200, { ok: true });
  }

  // ---- painel admin (exige X-Admin-Key) ----
  if (p === '/api/admin/db' && req.method === 'GET') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    const db = loadDB();
    return send(res, 200, {
      ok: true,
      users: db.users.map(adminUser),
      logins: db.logins.slice(-20).reverse(),
      total_users: db.users.length,
      total_logins: db.logins.length
    });
  }
  if (p === '/api/admin/db' && req.method === 'DELETE') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    saveDB({ users: [], logins: [], codes: [], seq: 1 });
    sessions.clear();
    return send(res, 200, { ok: true });
  }

  // Admin gera um novo código de resgate Premium (uso único).
  if (p === '/api/admin/premium/codes' && req.method === 'POST') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    const db = loadDB();
    let code;
    do { code = genCode(); } while (db.codes.some(c => c.code === code));
    db.codes.push({ code, criado_em: new Date().toISOString(), usado: false, usado_por: null, usado_em: null });
    saveDB(db);
    return send(res, 201, { ok: true, code });
  }
  // Admin lista os códigos já gerados (pra acompanhar o que foi usado).
  if (p === '/api/admin/premium/codes' && req.method === 'GET') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    const db = loadDB();
    return send(res, 200, { ok: true, codes: [...db.codes].reverse() });
  }
  // Admin apaga um código de premium ainda não usado (evita vazamento de código gerado por engano).
  if (p === '/api/admin/premium/codes' && req.method === 'DELETE') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    let body; try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const code = String(body.code || '').trim().toUpperCase();
    const db = loadDB();
    const idx = db.codes.findIndex(c => c.code === code && !c.usado);
    if (idx === -1) return send(res, 404, { ok: false, error: 'not_found' });
    db.codes.splice(idx, 1);
    saveDB(db);
    return send(res, 200, { ok: true });
  }

  // Admin concede/revoga Premium direto num usuário, sem precisar de código.
  if (p === '/api/admin/premium/grant' && req.method === 'POST') {
    if (!requireAdmin(req)) return send(res, 401, { ok: false, error: 'admin_key' });
    let body; try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const email = String(body.email || '').trim().toLowerCase();
    const grant = body.grant !== false;
    const db = loadDB();
    const user = db.users.find(u => u.email === email);
    if (!user) return send(res, 404, { ok: false, error: 'not_found' });
    user.premium = grant;
    user.premium_desde = grant ? (user.premium_desde || new Date().toISOString()) : null;
    saveDB(db);
    return send(res, 200, { ok: true, user: adminUser(user) });
  }

  // AURORA — chat com IA de verdade (só funciona com ANTHROPIC_API_KEY no .env).
  // Sem chave configurada, devolve 503 e o site cai automaticamente no modo
  // local (regras) — nada quebra pro usuário.
  if (p === '/api/ai/chat' && req.method === 'POST') {
    if (!ANTHROPIC_API_KEY) return send(res, 503, { ok: false, error: 'ai_not_configured' });
    if (rateLimited('ai:' + clientIp(req), 20, 60_000)) return send(res, 429, { ok: false, error: 'rate_limited' });
    let body; try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const message = String(body.message || '').trim().slice(0, 600);
    if (!message) return send(res, 400, { ok: false, error: 'empty' });
    const lang = ['pt', 'en', 'es'].includes(body.lang) ? body.lang : 'pt';

    // Contexto: só aceita o formato esperado, tudo mais é ignorado/cortado —
    // evita que um payload malicioso infle o prompt ou injete lixo.
    let context = { budget: null, days: null, people: null, month: null, likes: [], top: [] };
    if (body.context && typeof body.context === 'object') {
      const c = body.context;
      context.budget = Number.isFinite(Number(c.budget)) ? Number(c.budget) : null;
      context.days = Number.isFinite(Number(c.days)) ? Number(c.days) : null;
      context.people = c.people ? Number(c.people) : null;
      context.month = typeof c.month === 'string' ? c.month.slice(0, 24) : null;
      context.likes = Array.isArray(c.likes) ? c.likes.slice(0, 6).map(x => String(x).slice(0, 24)) : [];
      context.top = Array.isArray(c.top) ? c.top.slice(0, 3).map(o => ({
        city: String((o && o.city) || '').slice(0, 60),
        total: Number((o && o.total)) || 0,
        tags: Array.isArray(o && o.tags) ? o.tags.slice(0, 6).map(x => String(x).slice(0, 24)) : []
      })) : [];
    }
    const history = Array.isArray(body.history) ? body.history.slice(-6).map(m => ({
      role: m && m.role === 'assistant' ? 'assistant' : 'user',
      content: String((m && m.content) || '').slice(0, 600)
    })).filter(m => m.content) : [];

    const system = buildAuroraSystem(lang, context);
    const messages = [...history, { role: 'user', content: message }];
    try {
      const reply = await callAnthropic(messages, system);
      if (!reply) throw new Error('empty_reply');
      return send(res, 200, { ok: true, reply });
    } catch (e) {
      console.error('Erro AURORA (Anthropic):', e.message);
      return send(res, 502, { ok: false, error: 'ai_upstream' });
    }
  }

  // Usuário logado resgata um código pra virar Premium.
  if (p === '/api/premium/redeem' && req.method === 'POST') {
    if (rateLimited('redeem:' + clientIp(req), 10, 60_000)) return send(res, 429, { ok: false, error: 'rate_limited' });
    const email = sessionEmail(bearerToken(req));
    if (!email) return send(res, 401, { ok: false, error: 'no_session' });
    let body; try { body = await readJSON(req); } catch (e) { return send(res, 400, { ok: false, error: 'bad_json' }); }
    const code = String(body.code || '').trim().toUpperCase();
    if (!code) return send(res, 400, { ok: false, error: 'code_required' });
    const db = loadDB();
    const entry = db.codes.find(c => c.code === code);
    if (!entry) return send(res, 404, { ok: false, error: 'code_invalid' });
    if (entry.usado) return send(res, 409, { ok: false, error: 'code_used' });
    const user = db.users.find(u => u.email === email);
    if (!user) return send(res, 401, { ok: false, error: 'no_session' });
    entry.usado = true; entry.usado_por = email; entry.usado_em = new Date().toISOString();
    user.premium = true; user.premium_desde = user.premium_desde || entry.usado_em;
    saveDB(db);
    return send(res, 200, { ok: true, user: publicUser(user) });
  }

  return send(res, 404, { ok: false, error: 'not_found' });
}

// ---------- servidor estático ----------
function serveStatic(req, res, p) {
  let rel = p === '/' ? '/index.html' : decodeURIComponent(p);
  const file = path.normalize(path.join(ROOT, rel));
  const relFromRoot = path.relative(ROOT, file);
  if (relFromRoot.startsWith('..') || path.isAbsolute(relFromRoot)) {
    return send(res, 403, { ok: false, error: 'forbidden' });
  }
  const baseName = path.basename(file);
  if (FORBIDDEN_STATIC.has(baseName) || baseName.startsWith('.')) {
    return send(res, 404, { ok: false, error: 'not_found' });
  }
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 — não encontrado');
    }
    securityHeaders(res, req);
    const ext = path.extname(file);
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
    // Cache leve pros estáticos de SEO/ícone — não precisa revalidar a cada load.
    if (['.svg', '.ico', '.png'].includes(ext)) headers['Cache-Control'] = 'public, max-age=86400';
    res.writeHead(200, headers);
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://localhost').pathname;
  cors(req, res);
  securityHeaders(res, req);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (p.startsWith('/api/')) {
    try {
      await handleApi(req, res, p);
    } catch (e) {
      console.error('Erro na API:', e.message);
      send(res, 400, { ok: false, error: 'bad_request' });
    }
    return;
  }
  return serveStatic(req, res, p);
});

server.listen(PORT, () => {
  console.log('✅ RumoDB no ar → http://localhost:' + PORT);
});