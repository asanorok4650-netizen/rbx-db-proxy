// rbx-db-proxy: Roblox用プロキシ(R2キャッシュ付き)
//
//   GET  /asset/{id}   → R2にあればそれを返す(HIT)。無ければRobloxから取得し、R2に保存して返す(MISS)。
//                        応答ヘッダー X-Cache: HIT | MISS | BYPASS(R2未設定)
//   GET  /user/{id}    → Open Cloud(GET /cloud/v2/users/{id}, APIキー)で { id, name, displayName } を返す。R2に1日キャッシュ(X-Cache: HIT|MISS|BYPASS)
//   GET|POST /?url=    → users / avatar の公開APIの中継(APIキーは付けない)。PROXY_RULES にあるものだけ
//   GET  /health       → 接続確認(キーの値は返さない)
//   GET  /             → 管理ページ(パスコードで診断・キャッシュ確認/削除・使用量)
//   POST /admin        → 管理ページが呼ぶ。body: { passcode, action, assetId }
//
// 設定(Cloudflareダッシュボードの「ランタイム」側。ビルド側ではない):
//   ROBLOX_API_KEY  (シークレット) Open CloudのAPIキー(権限: legacy-asset:manage、/user/{id}を使うなら users の user.advanced:read も)
//   ADMIN_PASSCODE  (シークレット) 管理ページのパスコード(16文字以上推奨)
//   CF_API_TOKEN    (シークレット・任意) 使用量表示用。権限: Account Analytics の読み取り
//   ASSETS          (R2バインディング) wrangler.toml 参照。無いとキャッシュなしで動く
//   ALLOWED_ORIGIN / CF_ACCOUNT_ID / R2_BUCKET_NAME / MAX_OBJECT_BYTES (変数) wrangler.toml 参照
//   RL_REQUEST / RL_UPSTREAM (Rate Limitingバインディング・任意) wrangler.toml 参照
//
// 429の出どころは { error: 'RATE_LIMITED', source, retryAfter } の source で見分ける:
//   worker-request / worker-upstream … このWorkerのレート制限
//   roblox-edge … Roblox手前のCloudflareの制限(error code: 1015)。Workerの共有IPの混雑が原因の可能性
//   roblox      … Roblox側(APIキー)の制限
// Robloxへの問い合わせは、429のときWorker内で間隔を空けてATTEMPTS回までやり直す。

const ASSET_API = 'https://apis.roblox.com/asset-delivery-api/v1/assetId/';
const USER_API = 'https://apis.roblox.com/cloud/v2/users/';
const INTROSPECT_API = 'https://apis.roblox.com/api-keys/v1/introspect';
const EGRESS_IP_API = 'https://api64.ipify.org?format=json';
const GRAPHQL_API = 'https://api.cloudflare.com/client/v4/graphql';

// アセットの実体(Asset Deliveryが教えてくれるCDNのURL)として受け付けるホスト
const CDN_HOSTS = [/(^|\.)roblox\.com$/, /(^|\.)rbxcdn\.com$/];
const ASSET_PATH = /^\/asset\/(\d{1,19})$/;
const USER_PATH = /^\/user\/(\d{1,19})$/;
const USER_TTL_MS = 24 * 3600 * 1000;               // /user/{id} のR2キャッシュの有効期間(表示名は変わり得るので短め)

// 汎用の中継(?url=)で転送してよいリクエスト
const PROXY_RULES = [
  { host: 'users.roblox.com', method: 'POST', path: /^\/v1\/usernames\/users$/ },
  { host: 'users.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}$/ },
  { host: 'avatar.roblox.com', method: 'GET', path: /^\/v1\/users\/\d{1,19}\/avatar$/ },
];

const MAX_BODY_BYTES = 16 * 1024;                  // 中継するPOSTの本文の上限
const DEFAULT_MAX_OBJECT_BYTES = 32 * 1024 * 1024; // 1アセットの上限(超えたものは返さない/保存しない)
const ATTEMPTS = 3;                                // Robloxへの問い合わせの最大回数(429のとき)
const RETRY_AFTER_SECONDS = 30;                    // クライアントに伝える既定の待ち時間
const TEST_BODY_CHARS = 4000;

// 同じアセットを同時に要求されてもRobloxへの問い合わせは1回にする(同じアイソレート内のみ)
const inflight = new Map();
const userInflight = new Map();

const originList = (env) => String((env && env.ALLOWED_ORIGIN) || '*').split(',').map((s) => s.trim()).filter(Boolean);
const restricted = (env) => { const l = originList(env); return l.length > 0 && !l.includes('*'); };
const apiKeyOf = (env) => String((env && env.ROBLOX_API_KEY) || '').trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cdnHost = (u) => u.protocol === 'https:' && CDN_HOSTS.some((re) => re.test(u.hostname));
const clientKey = (req) => req.headers.get('CF-Connecting-IP') || 'unknown';

function corsHeaders(env, req) {
  const list = originList(env);
  const origin = req.headers.get('Origin');
  const allow = !restricted(env) ? '*' : (origin && list.includes(origin) ? origin : list[0]);
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': req.headers.get('Access-Control-Request-Headers') || 'Content-Type',
    'Access-Control-Expose-Headers': 'X-Cache, Retry-After',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
}

const json = (obj, status, cors, extra) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors, ...(extra || {}), 'Content-Type': 'application/json' } });
const tooMany = (cors, source, retryAfter) => {
  const sec = retryAfter || RETRY_AFTER_SECONDS;
  return json({ error: 'RATE_LIMITED', source, retryAfter: sec }, 429, cors, { 'Retry-After': String(sec) });
};

// Originはブラウザ以外なら偽装できる。「他のサイトからのうっかり利用」を防ぐ程度の保護。
function originOk(env, req) {
  if (!restricted(env)) return true;
  return originList(env).includes(req.headers.get('Origin'));
}

// Rate Limitingバインディングは「Cloudflareの拠点ごと」の近似値。無い環境では何もしない
async function limited(binding, key) {
  if (!binding || typeof binding.limit !== 'function') return false;
  try { const { success } = await binding.limit({ key }); return !success; } catch (e) { return false; }
}

// ---- Robloxへの問い合わせ ----

// 429の出どころを見分ける: error code: 1015 はRoblox手前のCloudflareの制限
async function classify429(r) {
  let text = '';
  try { text = await r.text(); } catch (e) { /* 無視 */ }
  return /error code: 1015/.test(text) ? 'roblox-edge' : 'roblox';
}

function retryDelay(attempt, r) {
  const ra = Number(r.headers.get('Retry-After'));
  if (Number.isFinite(ra) && ra > 0 && ra <= 3) return ra * 1000;
  return 400 * Math.pow(3, attempt) + Math.floor(Math.random() * 200);
}

// 429の間は間隔を空けてやり直す。戻り値: { r } または { limited: { source, retryAfter } }
async function fetchRetry(url, init) {
  let lim = null;
  for (let i = 0; i < ATTEMPTS; i++) {
    const r = await fetch(url, init);
    if (r.status !== 429) return { r };
    const source = await classify429(r);
    const ra = Number(r.headers.get('Retry-After'));
    lim = { source, retryAfter: ra > 0 ? Math.min(Math.ceil(ra), 3600) : RETRY_AFTER_SECONDS };
    if (i < ATTEMPTS - 1) await sleep(retryDelay(i, r));
  }
  return { limited: lim };
}

const fail = (status, error, extra) => ({ ok: false, status, error, ...(extra || {}) });

// Robloxからアセットを取得: Asset Delivery(APIキー) → CDN
async function fetchAsset(id, apiKey, maxBytes) {
  try {
    const m = await fetchRetry(ASSET_API + id, { headers: { 'x-api-key': apiKey, Accept: 'application/json' } });
    if (m.limited) return fail(429, 'RATE_LIMITED', m.limited);
    const r = m.r;
    if (r.status === 401 || r.status === 403) return fail(401, 'KEY_REJECTED', { upstreamStatus: r.status });
    if (r.status === 404) return fail(404, 'NOT_FOUND');
    if (!r.ok) return fail(502, 'UPSTREAM', { upstreamStatus: r.status });
    const meta = await r.json();

    let loc;
    try { loc = new URL(meta && meta.location); } catch (e) { return fail(502, 'NO_LOCATION'); }
    if (!cdnHost(loc)) return fail(502, 'BAD_LOCATION');

    const c = await fetchRetry(loc.toString(), { redirect: 'manual' });
    if (c.limited) return fail(429, 'RATE_LIMITED', c.limited);
    if (!c.r.ok) return fail(502, 'CDN', { upstreamStatus: c.r.status });
    if (Number(c.r.headers.get('Content-Length')) > maxBytes) return fail(413, 'TOO_LARGE');

    const type = c.r.headers.get('Content-Type') || 'application/octet-stream';
    const buf = await c.r.arrayBuffer();
    return { ok: true, buf, type, storable: buf.byteLength <= maxBytes };
  } catch (e) {
    return fail(502, 'UPSTREAM');
  }
}

async function handleAsset(id, env, req, ctx, cors) {
  const key = 'asset/' + id;
  const bucket = env && env.ASSETS;

  // 1. R2にあればそれを返す(Robloxを呼ばない)
  if (bucket) {
    try {
      const obj = await bucket.get(key);
      if (obj) {
        return new Response(obj.body, {
          status: 200,
          headers: {
            ...cors,
            'Content-Type': (obj.httpMetadata && obj.httpMetadata.contentType) || 'application/octet-stream',
            'Cache-Control': 'public, max-age=86400',
            'X-Cache': 'HIT',
          },
        });
      }
    } catch (e) { /* R2に失敗してもRobloxから取れるので続行 */ }
  }

  // 2. 無ければRobloxから取得
  const apiKey = apiKeyOf(env);
  if (!apiKey) return json({ error: 'NO_API_KEY' }, 503, cors);
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return tooMany(cors, 'worker-upstream');

  const maxBytes = Number(env.MAX_OBJECT_BYTES) > 0 ? Number(env.MAX_OBJECT_BYTES) : DEFAULT_MAX_OBJECT_BYTES;
  let p = inflight.get(id);
  if (!p) {
    p = fetchAsset(id, apiKey, maxBytes)
      .then((res) => {
        if (res.ok && res.storable && bucket) {
          ctx.waitUntil(
            bucket.put(key, res.buf, {
              httpMetadata: { contentType: res.type },
              customMetadata: { fetchedAt: String(Date.now()) },
            }).catch(() => {}),
          );
        }
        return res;
      })
      .finally(() => inflight.delete(id));
    inflight.set(id, p);
  }
  const res = await p;
  if (!res.ok) {
    if (res.status === 429) return tooMany(cors, res.source, res.retryAfter);
    return json({ error: res.error, status: res.upstreamStatus }, res.status, cors);
  }
  return new Response(res.buf, {
    status: 200,
    headers: { ...cors, 'Content-Type': res.type, 'Cache-Control': 'public, max-age=86400', 'X-Cache': bucket ? 'MISS' : 'BYPASS' },
  });
}

// Open Cloud でユーザー情報(ユーザー名・表示名)を取得。キー無しの公開APIより429になりにくい(キー単位の枠 1000回/分)
async function fetchUser(id, apiKey) {
  try {
    const m = await fetchRetry(USER_API + id, { headers: { 'x-api-key': apiKey, Accept: 'application/json' } });
    if (m.limited) return fail(429, 'RATE_LIMITED', m.limited);
    const r = m.r;
    if (r.status === 401 || r.status === 403) return fail(401, 'KEY_REJECTED', { upstreamStatus: r.status });
    if (r.status === 404) return fail(404, 'NOT_FOUND');
    if (!r.ok) return fail(502, 'UPSTREAM', { upstreamStatus: r.status });
    const j = await r.json();
    const name = j && typeof j.name === 'string' ? j.name : '';
    if (!name) return fail(502, 'NO_NAME');
    const displayName = j && typeof j.displayName === 'string' && j.displayName ? j.displayName : name;
    return { ok: true, body: JSON.stringify({ id: Number(id), name, displayName }) };
  } catch (e) {
    return fail(502, 'UPSTREAM');
  }
}

async function handleUser(id, env, req, ctx, cors) {
  const key = 'user/' + id;
  const bucket = env && env.ASSETS;
  const reply = (body, xcache) => new Response(body, {
    status: 200,
    headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=3600', 'X-Cache': xcache },
  });

  // 1. R2に新しいものがあれば返す(Robloxを呼ばない)
  if (bucket) {
    try {
      const obj = await bucket.get(key);
      if (obj) {
        const at = Number(obj.customMetadata && obj.customMetadata.fetchedAt) || 0;
        if (Date.now() - at < USER_TTL_MS) return reply(await obj.text(), 'HIT');
      }
    } catch (e) { /* R2に失敗してもRobloxから取れるので続行 */ }
  }

  // 2. 無ければOpen Cloudから取得
  const apiKey = apiKeyOf(env);
  if (!apiKey) return json({ error: 'NO_API_KEY' }, 503, cors);
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return tooMany(cors, 'worker-upstream');

  let p = userInflight.get(id);
  if (!p) {
    p = fetchUser(id, apiKey)
      .then((res) => {
        if (res.ok && bucket) {
          ctx.waitUntil(
            bucket.put(key, res.body, {
              httpMetadata: { contentType: 'application/json' },
              customMetadata: { fetchedAt: String(Date.now()) },
            }).catch(() => {}),
          );
        }
        return res;
      })
      .finally(() => userInflight.delete(id));
    userInflight.set(id, p);
  }
  const res = await p;
  if (!res.ok) {
    if (res.status === 429) return tooMany(cors, res.source, res.retryAfter);
    return json({ error: res.error, status: res.upstreamStatus }, res.status, cors);
  }
  return reply(res.body, bucket ? 'MISS' : 'BYPASS');
}

// users / avatar の公開APIの中継(APIキーは付けない。リダイレクトは追わない)
async function handleProxy(req, env, cors) {
  const raw = new URL(req.url).searchParams.get('url');
  let target;
  try { target = new URL(raw); } catch (e) { return new Response('bad url', { status: 400, headers: cors }); }
  const ok = target.protocol === 'https:' && !target.username && !target.password && !target.port
    && PROXY_RULES.some((r) => r.host === target.hostname && r.method === req.method && r.path.test(target.pathname));
  if (!ok) return new Response('not allowed', { status: 403, headers: cors });

  let body;
  if (req.method === 'POST') {
    if (Number(req.headers.get('Content-Length')) > MAX_BODY_BYTES) return new Response('too large', { status: 413, headers: cors });
    body = await req.arrayBuffer();
    if (body.byteLength > MAX_BODY_BYTES) return new Response('too large', { status: 413, headers: cors });
  }
  if (await limited(env.RL_UPSTREAM, clientKey(req))) return tooMany(cors, 'worker-upstream');

  const init = { method: req.method, headers: { Accept: req.headers.get('Accept') || '*/*' }, redirect: 'manual' };
  if (body) { init.headers['Content-Type'] = req.headers.get('Content-Type') || 'application/json'; init.body = body; }

  let upstream;
  try { upstream = await fetch(target.toString(), init); }
  catch (e) { return new Response('upstream error', { status: 502, headers: cors }); }
  if (upstream.status >= 300 && upstream.status < 400) return new Response('redirect not allowed', { status: 502, headers: cors });

  const h = new Headers(upstream.headers);
  h.delete('set-cookie');
  for (const [k, v] of Object.entries(cors)) h.set(k, v);
  return new Response(upstream.body, { status: upstream.status, headers: h });
}

// ---- 管理ページ ----
// CORSヘッダは付けない(他サイトからは結果を読めない)。Origin制限・レート制限より前に処理するので、詰まっていても開ける。

const ADMIN_HTML = `<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>rbx-db-proxy 管理</title>
<style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem;line-height:1.6}
input,button{font-size:1rem;padding:.6rem;width:100%;box-sizing:border-box;margin:.3rem 0}
button{cursor:pointer}
#st{padding:.6rem;border-radius:.4rem;background:#8882}
pre{padding:.6rem;border-radius:.4rem;background:#8882;white-space:pre-wrap;word-break:break-all;font-size:.8rem}
</style></head><body>
<h1>rbx-db-proxy 管理</h1>
<p id="st">状態を確認中…</p>
<input id="pw" type="password" placeholder="パスコード" autocomplete="current-password">
<input id="aid" type="text" inputmode="numeric" placeholder="アセットID(数字)">
<button id="test">診断テスト(キー・接続元IP・Robloxの応答)</button>
<button id="stat">キャッシュされているか確認</button>
<button id="purge">キャッシュを削除(次回取り直す)</button>
<button id="usage">R2の使用量を確認</button>
<pre id="out" hidden></pre>
<p><small>診断テストはRobloxを直接呼び、APIキーの枠を消費します(R2には保存しません)。キャッシュ確認はR2の読み取り操作を1回使います。</small></p>
<script>
const $=(i)=>document.getElementById(i);
async function refresh(){
  try{
    const h=await (await fetch('/health')).json();
    $('st').textContent='キー: '+(h.hasApiKey?'あり':'なし')+' / R2キャッシュ: '+(h.hasCache?'あり':'なし')+' / レート制限: '+(h.rateLimit?'設定あり':'設定なし');
  }catch(e){$('st').textContent='状態を取得できませんでした';}
}
async function call(action){
  const o=$('out');o.hidden=false;o.textContent='送信中…';
  try{
    const r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:$('pw').value,action:action,assetId:$('aid').value})});
    o.textContent=JSON.stringify(await r.json(),null,2);
  }catch(e){o.textContent='通信に失敗しました';}
}
$('test').onclick=()=>call('test');
$('stat').onclick=()=>call('stat');
$('purge').onclick=()=>call('purge');
$('usage').onclick=()=>call('usage');
refresh();
</script></body></html>`;

const adminJson = (obj, status) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });

// パスコードの比較(長さや一致位置が時間でばれないようハッシュにして全バイト比べる)
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(a)), crypto.subtle.digest('SHA-256', enc.encode(b))]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

// 診断テスト: キーの形(末尾6文字)・接続元IP・Robloxのキー検査・Asset Deliveryの応答をそのまま返す
async function runTest(env, rawId) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ error: 'BAD_ASSET_ID' }, 400);
  const raw = String((env && env.ROBLOX_API_KEY) || '');
  const key = raw.trim();
  if (!key) return adminJson({ error: 'NO_API_KEY' }, 503);

  const out = {
    keyInfo: {
      length: raw.length, trimmedLength: key.length, hadOuterWhitespace: raw !== key,
      printableAsciiOnly: /^[\x21-\x7e]+$/.test(key), last6: key.slice(-6),
    },
  };
  try { out.egress = JSON.parse(await (await fetch(EGRESS_IP_API)).text()); } catch (e) { out.egress = { error: 'FETCH_FAILED' }; }
  try {
    const r = await fetch(INTROSPECT_API, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ apiKey: key }) });
    out.introspect = { status: r.status, body: (await r.text()).slice(0, TEST_BODY_CHARS) };
  } catch (e) { out.introspect = { error: 'FETCH_FAILED' }; }

  const t0 = Date.now();
  try {
    const r = await fetch(ASSET_API + id, { headers: { 'x-api-key': key, Accept: 'application/json' } });
    const text = await r.text();
    const headers = {};
    r.headers.forEach((v, k) => { if (k !== 'set-cookie') headers[k] = v; });
    out.asset = { ok: r.ok, status: r.status, statusText: r.statusText, ms: Date.now() - t0, headers, body: text.slice(0, TEST_BODY_CHARS), truncated: text.length > TEST_BODY_CHARS };
  } catch (e) { out.asset = { error: 'FETCH_FAILED' }; }
  return adminJson(out, 200);
}

// R2の使用量(GraphQL Analytics API)。保存量は直近3日の最新値、操作回数は今月(UTC)の合計
async function runUsage(env) {
  const token = env.CF_API_TOKEN, account = env.CF_ACCOUNT_ID, bucket = env.R2_BUCKET_NAME;
  if (!token || !account || !bucket) {
    return adminJson({ error: 'USAGE_NOT_CONFIGURED', need: ['CF_API_TOKEN(シークレット)', 'CF_ACCOUNT_ID(変数)', 'R2_BUCKET_NAME(変数)'] }, 503);
  }
  const now = new Date();
  const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  const storageStart = new Date(now.getTime() - 3 * 24 * 3600 * 1000);
  const query = 'query R2Usage($accountTag: String!, $bucket: String!, $monthStart: Time!, $storageStart: Time!, $end: Time!) {'
    + ' viewer { accounts(filter: { accountTag: $accountTag }) {'
    + ' storage: r2StorageAdaptiveGroups(limit: 1, filter: { datetime_geq: $storageStart, datetime_leq: $end, bucketName: $bucket }, orderBy: [datetime_DESC]) { max { objectCount payloadSize metadataSize } dimensions { datetime } }'
    + ' ops: r2OperationsAdaptiveGroups(limit: 10000, filter: { datetime_geq: $monthStart, datetime_leq: $end, bucketName: $bucket }) { sum { requests } dimensions { actionType } }'
    + ' } } }';
  try {
    const r = await fetch(GRAPHQL_API, {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, variables: { accountTag: account, bucket, monthStart: monthStart.toISOString(), storageStart: storageStart.toISOString(), end: now.toISOString() } }),
    });
    const data = await r.json();
    const acc = data && data.data && data.data.viewer && data.data.viewer.accounts && data.data.viewer.accounts[0];
    const s = acc && acc.storage && acc.storage[0];
    const operations = {};
    ((acc && acc.ops) || []).forEach((o) => { operations[o.dimensions.actionType] = (operations[o.dimensions.actionType] || 0) + o.sum.requests; });
    return adminJson({
      httpStatus: r.status,
      monthStartUtc: monthStart.toISOString(),
      storage: s ? {
        objectCount: s.max.objectCount, payloadBytes: s.max.payloadSize, metadataBytes: s.max.metadataSize,
        payloadMB: Math.round((s.max.payloadSize / 1048576) * 10) / 10, at: s.dimensions.datetime,
      } : null,
      operations,
      errors: data && data.errors,
    }, 200);
  } catch (e) {
    return adminJson({ error: 'GRAPHQL_FAILED' }, 502);
  }
}

async function handleAdmin(req, env) {
  if (req.method === 'GET') {
    return new Response(ADMIN_HTML, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'",
      },
    });
  }
  if (!env || !env.ADMIN_PASSCODE) return adminJson({ error: 'NO_PASSCODE_CONFIGURED' }, 503);
  if (Number(req.headers.get('Content-Length')) > 1024) return adminJson({ error: 'TOO_LARGE' }, 413);

  let b;
  try { b = await req.json(); } catch (e) { b = {}; }
  const good = b && typeof b.passcode === 'string' && await safeEqual(b.passcode, String(env.ADMIN_PASSCODE));
  if (!good) {
    await sleep(1000); // 総当たりを遅くする(パスコードは長くすること)
    return adminJson({ error: 'BAD_PASSCODE' }, 401);
  }

  if (b.action === 'test') return runTest(env, b.assetId);
  if (b.action === 'usage') return runUsage(env);

  if (b.action === 'stat' || b.action === 'purge') {
    const id = String(b.assetId || '').trim();
    if (!/^\d{1,19}$/.test(id)) return adminJson({ error: 'BAD_ASSET_ID' }, 400);
    if (!env.ASSETS) return adminJson({ error: 'NO_R2_BINDING' }, 503);
    try {
      if (b.action === 'purge') { await env.ASSETS.delete('asset/' + id); return adminJson({ ok: true, purged: id }, 200); }
      const o = await env.ASSETS.head('asset/' + id);
      return adminJson(o
        ? { cached: true, size: o.size, uploaded: o.uploaded, contentType: o.httpMetadata && o.httpMetadata.contentType }
        : { cached: false }, 200);
    } catch (e) {
      return adminJson({ error: 'R2_ERROR' }, 500);
    }
  }
  return adminJson({ error: 'UNKNOWN_ACTION' }, 400);
}

export default {
  async fetch(req, env, ctx) {
    const cors = corsHeaders(env, req);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'GET' && req.method !== 'POST') return new Response('Method Not Allowed', { status: 405, headers: cors });
    const url = new URL(req.url);

    if (url.pathname === '/health') {
      return json({
        ok: true, hasApiKey: Boolean(apiKeyOf(env)), hasCache: Boolean(env && env.ASSETS),
        originRestricted: restricted(env), rateLimit: Boolean(env && env.RL_REQUEST && env.RL_UPSTREAM), version: 2, userApi: true,
      }, 200, cors);
    }
    // 管理ページ(Origin制限・レート制限より前)。/ に ?url= が付いていれば従来どおり中継
    if ((url.pathname === '/' && req.method === 'GET' && !url.searchParams.has('url')) || (url.pathname === '/admin' && req.method === 'POST')) {
      return handleAdmin(req, env);
    }
    if (!originOk(env, req)) return json({ error: 'ORIGIN_NOT_ALLOWED' }, 403, cors);
    if (await limited(env.RL_REQUEST, clientKey(req))) return tooMany(cors, 'worker-request');

    const m = ASSET_PATH.exec(url.pathname);
    if (m && req.method === 'GET') return handleAsset(m[1], env, req, ctx, cors);
    const u = USER_PATH.exec(url.pathname);
    if (u && req.method === 'GET') return handleUser(u[1], env, req, ctx, cors);
    return handleProxy(req, env, cors);
  },
};
