// RaeBlox ログイン: RobloxユーザーID + 独自パスワード
// 本人確認は、Robloxのプロフィール説明文にワンタイムコードを貼ってもらい、公開API(users.roblox.com)で確認する。
// 保存先は既存のR2(ASSETS)の auth/ 以下(新しいバインディングは不要)。セッションは Authorization: Bearer <token>。
//
//   POST /auth/start    { userId, purpose: 'register' | 'reset' } → { ticket, code, purpose, expiresIn, user }
//   POST /auth/register { userId, password, ticket }              → { token, user }   (説明文にcodeがあること)
//   POST /auth/reset    { userId, password, ticket }              → { token, user }   (既存アカウントのパスワードを変更。他のセッションは全て無効)
//   POST /auth/login    { userId, password }                      → { token, user }
//   GET  /auth/me       (Authorization: Bearer <token>)           → { user }
//   POST /auth/logout   (Authorization: Bearer <token>)           → { ok: true }
//
// ticket は start を呼んだ本人だけが持つ秘密。他人が同じユーザーIDで start しても、そのコードでは登録できない。
// パスワードは PBKDF2-SHA256(100,000回)+ ソルトでハッシュ化して保存する(Workersの上限が100,000回)。
// 無料プランでCPU時間の上限(エラー1102)に当たる場合は、PBKDF2_ITER を下げるか有料プランにする(下げた場合、既存アカウントは iter を記録しているので影響しない)。

const PBKDF2_ITER = 100000;
const PENDING_TTL_MS = 15 * 60 * 1000;        // コードの有効期間
const SESSION_TTL_MS = 30 * 24 * 3600 * 1000; // ログインの有効期間
const MAX_FAILS = 10;                         // この回数失敗したら一時ロック
const LOCK_MS = 10 * 60 * 1000;
const MAX_BODY = 4096;
const USER_ID = /^[1-9]\d{0,18}$/;
const PROFILE_API = 'https://users.roblox.com/v1/users/';
const CODE_CHARS = 'bcdfghjklmnpqrstvwxz';    // 母音なし(意図しない単語になって、Robloxのフィルターに伏せ字にされるのを避ける)

const enc = new TextEncoder();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- 共通(index.js と同じ方針のCORS / Origin制限) ----
const originList = (env) => String((env && env.ALLOWED_ORIGIN) || '*').split(',').map((s) => s.trim()).filter(Boolean);
const restricted = (env) => { const l = originList(env); return l.length > 0 && !l.includes('*'); };

function corsHeaders(env, req) {
  const list = originList(env);
  const origin = req.headers.get('Origin');
  const allow = !restricted(env) ? '*' : (origin && list.includes(origin) ? origin : list[0]);
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': req.headers.get('Access-Control-Request-Headers') || 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
}
const json = (obj, status, cors, extra) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, ...(extra || {}), 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
const err = (cors, status, error, extra) => json({ ok: false, error, ...(extra || {}) }, status, cors);
const clientKey = (req) => req.headers.get('CF-Connecting-IP') || 'unknown';

async function limited(binding, key) {
  if (!binding || typeof binding.limit !== 'function') return false;
  try { const { success } = await binding.limit({ key }); return !success; } catch (e) { return false; }
}

// ---- 小道具 ----
function b64url(buf) {
  let s = '';
  for (const x of new Uint8Array(buf)) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out;
}
const randomB64 = (n) => b64url(crypto.getRandomValues(new Uint8Array(n)));
async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return Array.from(new Uint8Array(d)).map((x) => x.toString(16).padStart(2, '0')).join('');
}
function makeCode() {
  let s = '';
  for (const x of crypto.getRandomValues(new Uint8Array(12))) s += CODE_CHARS[x % CODE_CHARS.length];
  return 'raebox-' + s;
}
async function derive(password, salt, iter) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, key, 256));
}
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
async function readBody(req) {
  if (Number(req.headers.get('Content-Length')) > MAX_BODY) return null;
  try {
    const t = await req.text();
    if (t.length > MAX_BODY) return null;
    const j = JSON.parse(t);
    return j && typeof j === 'object' && !Array.isArray(j) ? j : null;
  } catch (e) { return null; }
}
const validPassword = (p) => typeof p === 'string' && p.length >= 8 && p.length <= 128;
const idOf = (v) => (typeof v === 'number' || typeof v === 'string') && USER_ID.test(String(v)) ? String(v) : null;
const publicUser = (a) => ({ userId: a.userId, name: a.name, displayName: a.displayName });

// ---- R2 ----
const accKey = (id) => 'auth/account/' + id;
const failKey = (id) => 'auth/fail/' + id;
const pendKey = (id, th) => 'auth/pending/' + id + '/' + th;
const sessKey = (id, th) => 'auth/session/' + id + '/' + th;
async function getJson(env, key) {
  try {
    const o = await env.ASSETS.get(key);
    return o ? JSON.parse(await o.text()) : null;
  } catch (e) { return null; }
}
const putJson = (env, key, obj, opts) =>
  env.ASSETS.put(key, JSON.stringify(obj), { httpMetadata: { contentType: 'application/json' }, ...(opts || {}) });

// ---- Robloxのプロフィール(公開API) ----
async function fetchProfile(userId) {
  const ATTEMPTS = 3;
  for (let i = 0; i < ATTEMPTS; i++) {
    const last = i === ATTEMPTS - 1;
    let r;
    try { r = await fetch(PROFILE_API + userId, { headers: { Accept: 'application/json' } }); }
    catch (e) { if (last) return { status: 502, error: 'UPSTREAM' }; await sleep(400 * Math.pow(3, i)); continue; }
    if (r.status === 400 || r.status === 404) return { status: 404, error: 'USER_NOT_FOUND' };
    if (r.status === 429 || r.status >= 500) {
      if (last) return r.status === 429 ? { status: 429, error: 'RATE_LIMITED', retryAfter: 30 } : { status: 502, error: 'UPSTREAM' };
      try { await r.body.cancel(); } catch (e) { /* 無視 */ }
      await sleep(400 * Math.pow(3, i));
      continue;
    }
    if (!r.ok) return { status: 502, error: 'UPSTREAM' };
    try {
      const j = await r.json();
      if (j && j.isBanned) return { status: 403, error: 'USER_BANNED' };
      const name = String((j && j.name) || '');
      return { ok: true, name, displayName: String((j && j.displayName) || name), description: String((j && j.description) || '') };
    } catch (e) { return { status: 502, error: 'UPSTREAM' }; }
  }
  return { status: 502, error: 'UPSTREAM' };
}
const profileFail = (cors, p) => err(cors, p.status, p.error, p.retryAfter ? { retryAfter: p.retryAfter } : undefined);

// ---- セッション ----
async function createSession(env, userId) {
  const rand = randomB64(32);
  await putJson(env, sessKey(userId, await sha256hex(rand)), { createdAt: Date.now() });
  return userId + '.' + rand;
}
async function sessionOf(env, req) {
  const m = /^Bearer (\d{1,19})\.([A-Za-z0-9_-]{20,100})$/.exec(req.headers.get('Authorization') || '');
  if (!m) return null;
  const key = sessKey(m[1], await sha256hex(m[2]));
  const s = await getJson(env, key);
  if (!s || !(Date.now() - s.createdAt < SESSION_TTL_MS)) return null;
  const account = await getJson(env, accKey(m[1]));
  return account ? { key, account } : null;
}
async function deleteSessions(env, userId) {
  for (let i = 0; i < 10; i++) {
    const l = await env.ASSETS.list({ prefix: 'auth/session/' + userId + '/', limit: 1000 });
    if (l.objects.length) await env.ASSETS.delete(l.objects.map((o) => o.key));
    if (!l.truncated) break;
  }
}

// ---- 各エンドポイント ----
async function handleStart(env, req, cors) {
  const b = await readBody(req);
  const userId = b && idOf(b.userId);
  if (!userId) return err(cors, 400, 'BAD_REQUEST');
  const purpose = b.purpose === 'reset' ? 'reset' : 'register';
  const exists = Boolean(await env.ASSETS.head(accKey(userId)));
  if (purpose === 'register' && exists) return err(cors, 409, 'ACCOUNT_EXISTS');
  if (purpose === 'reset' && !exists) return err(cors, 404, 'NO_ACCOUNT');
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return err(cors, 429, 'RATE_LIMITED', { source: 'worker-upstream', retryAfter: 30 });

  const p = await fetchProfile(userId); // ユーザーの存在確認も兼ねる
  if (!p.ok) return profileFail(cors, p);
  const ticket = randomB64(24);
  const code = makeCode();
  await putJson(env, pendKey(userId, await sha256hex(ticket)), { purpose, code, createdAt: Date.now() });
  return json({ ok: true, ticket, code, purpose, expiresIn: PENDING_TTL_MS / 1000, user: { userId, name: p.name, displayName: p.displayName } }, 200, cors);
}

async function handleComplete(env, req, cors, purpose) {
  const b = await readBody(req);
  const userId = b && idOf(b.userId);
  if (!userId || typeof b.ticket !== 'string' || b.ticket.length < 16 || b.ticket.length > 100) return err(cors, 400, 'BAD_REQUEST');
  if (!validPassword(b.password)) return err(cors, 400, 'BAD_PASSWORD'); // 8〜128文字

  const pk = pendKey(userId, await sha256hex(b.ticket));
  const pend = await getJson(env, pk);
  if (!pend || pend.purpose !== purpose) return err(cors, 400, 'NO_PENDING');
  if (!(Date.now() - pend.createdAt < PENDING_TTL_MS)) {
    await env.ASSETS.delete(pk);
    return err(cors, 400, 'CODE_EXPIRED');
  }
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return err(cors, 429, 'RATE_LIMITED', { source: 'worker-upstream', retryAfter: 30 });

  const p = await fetchProfile(userId);
  if (!p.ok) return profileFail(cors, p);
  if (!p.description.includes(pend.code)) return err(cors, 400, 'CODE_NOT_FOUND'); // 説明文に見つからない(反映に少し時間がかかることも)

  const now = Date.now();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(b.password, salt, PBKDF2_ITER);
  const rec = { v: 1, userId, name: p.name, displayName: p.displayName, salt: b64url(salt), hash: b64url(hash), iter: PBKDF2_ITER, createdAt: now, updatedAt: now };

  if (purpose === 'register') {
    const put = await env.ASSETS.put(accKey(userId), JSON.stringify(rec), { httpMetadata: { contentType: 'application/json' }, onlyIf: { etagDoesNotMatch: '*' } });
    if (!put) return err(cors, 409, 'ACCOUNT_EXISTS'); // 同時に登録された
  } else {
    const old = await getJson(env, accKey(userId));
    if (!old) return err(cors, 404, 'NO_ACCOUNT');
    rec.createdAt = old.createdAt || now;
    await putJson(env, accKey(userId), rec);
    await deleteSessions(env, userId);
    await env.ASSETS.delete(failKey(userId));
  }
  await env.ASSETS.delete(pk);
  return json({ ok: true, token: await createSession(env, userId), user: publicUser(rec) }, 200, cors);
}

async function handleLogin(env, req, cors) {
  const b = await readBody(req);
  const userId = b && idOf(b.userId);
  if (!userId || typeof b.password !== 'string' || b.password.length > 128) return err(cors, 400, 'BAD_REQUEST');

  const now = Date.now();
  const fail = (await getJson(env, failKey(userId))) || { count: 0, lockedUntil: 0 };
  if (fail.lockedUntil > now) return err(cors, 429, 'LOCKED', { retryAfter: Math.ceil((fail.lockedUntil - now) / 1000) });

  const acc = await getJson(env, accKey(userId));
  let ok = false;
  if (acc) ok = bytesEqual(await derive(b.password, unb64url(acc.salt), acc.iter || PBKDF2_ITER), unb64url(acc.hash));
  else await derive(b.password, new Uint8Array(16), PBKDF2_ITER); // アカウントの有無が応答時間でばれないようにする

  if (!ok) {
    const count = fail.count + 1;
    await putJson(env, failKey(userId), { count: count >= MAX_FAILS ? 0 : count, lockedUntil: count >= MAX_FAILS ? now + LOCK_MS : 0 });
    return err(cors, 401, 'BAD_CREDENTIALS');
  }
  if (fail.count) await env.ASSETS.delete(failKey(userId));
  return json({ ok: true, token: await createSession(env, userId), user: publicUser(acc) }, 200, cors);
}

export async function handleAuth(req, env, ctx) {
  const cors = corsHeaders(env, req);
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (restricted(env) && !originList(env).includes(req.headers.get('Origin'))) return err(cors, 403, 'ORIGIN_NOT_ALLOWED');
  if (!env || !env.ASSETS) return err(cors, 503, 'NO_R2_BINDING');
  if (await limited(env.RL_REQUEST, clientKey(req))) return err(cors, 429, 'RATE_LIMITED', { source: 'worker-request', retryAfter: 30 });

  const path = new URL(req.url).pathname;
  try {
    if (req.method === 'POST') {
      if (path === '/auth/start') return await handleStart(env, req, cors);
      if (path === '/auth/register') return await handleComplete(env, req, cors, 'register');
      if (path === '/auth/reset') return await handleComplete(env, req, cors, 'reset');
      if (path === '/auth/login') return await handleLogin(env, req, cors);
      if (path === '/auth/logout') {
        const s = await sessionOf(env, req);
        if (s) await env.ASSETS.delete(s.key);
        return json({ ok: true }, 200, cors);
      }
    }
    if (req.method === 'GET' && path === '/auth/me') {
      const s = await sessionOf(env, req);
      return s ? json({ ok: true, user: publicUser(s.account) }, 200, cors) : err(cors, 401, 'NOT_LOGGED_IN');
    }
  } catch (e) {
    return err(cors, 500, 'INTERNAL');
  }
  return err(cors, 404, 'NOT_FOUND');
}
