// rbx-db-proxy: Roblox用プロキシ(R2キャッシュ付き)
//
//   GET  /asset/{id}   → R2にあればそれを返す(HIT)。無ければRobloxから取得し、R2に保存して返す(MISS)。
//                        応答ヘッダー X-Cache: HIT | MISS | BYPASS(R2未設定)
//   GET  /user/{id}    → Open Cloud(GET /cloud/v2/users/{id}, APIキー)で { id, name, displayName } を返す。R2に1日キャッシュ(X-Cache: HIT|MISS|BYPASS)
//   GET|POST /?url=    → users / avatar の公開APIの中継(APIキーは付けない)。PROXY_RULES にあるものだけ
//   GET  /health       → 接続確認(キーの値は返さない)
//   GET  /             → 管理ページ(パスコードで診断・キャッシュ確認/削除・使用量)
//   POST /admin        → 管理ページが呼ぶ。body: { passcode, action, assetId | userId }
//                        action: test | stat | purge | usage | user(Open Cloudのユーザー取得を診断) | avatar(v1とv4のアバター取得を比較)
//                                cache(1アセットをRobloxから取得してR2に保存。force:trueで取り直し) | avatarCache(アバター情報をR2のavatar/{id}に保存しアセット一覧を返す。skip:[カテゴリ]で除外) | sweep(R2のasset/を種別で探索。dryRun:falseで削除。categories:[animation|layered])
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
  { host: 'avatar.roblox.com', method: 'GET', path: /^\/v4\/avatar\/users\/\d{1,19}$/ },
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
  const ra = r ? Number(r.headers.get('Retry-After')) : NaN;
  if (Number.isFinite(ra) && ra > 0 && ra <= 3) return ra * 1000;
  return 400 * Math.pow(3, attempt) + Math.floor(Math.random() * 200);
}

// 429・5xx・ネットワークエラーの間は間隔を空けてやり直す。戻り値: { r } または { limited: { source, retryAfter } }
// (5xxが続いた場合は最後の応答を { r } で返す。ネットワークエラーが続いた場合は例外)
async function fetchRetry(url, init) {
  let lim = null;
  for (let i = 0; i < ATTEMPTS; i++) {
    const last = i === ATTEMPTS - 1;
    let r;
    try { r = await fetch(url, init); }
    catch (e) { if (last) throw e; await sleep(retryDelay(i)); continue; }
    if (r.status >= 500 && r.status < 600 && !last) {
      try { await r.body.cancel(); } catch (e) { /* 無視 */ }
      await sleep(retryDelay(i));
      continue;
    }
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

const maxBytesOf = (env) => (Number(env && env.MAX_OBJECT_BYTES) > 0 ? Number(env.MAX_OBJECT_BYTES) : DEFAULT_MAX_OBJECT_BYTES);

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
<h2>ユーザー / アバター取得テスト</h2>
<input id="uid" type="text" inputmode="numeric" placeholder="ユーザーID(数字)">
<button id="utest">ユーザー情報(Open Cloud)を取得</button>
<button id="avcmp">アバター v1 と v4 を比較</button>
<h2>Robloxから読み込んでR2に保存</h2>
<input id="cids" type="text" placeholder="アセットID(複数ならカンマ・空白区切り)">
<button id="cache">アセットを取得してR2に保存</button>
<button id="avcache">アバターを取得して、含まれるアセットごとR2に保存</button>
<label><input id="force" type="checkbox" style="width:auto"> 既にR2にあっても取り直す</label>
<h2>除外カテゴリ / 不要物の削除</h2>
<label><input id="cat_animation" type="checkbox" style="width:auto" checked> アニメーション・エモート</label><br>
<label><input id="cat_layered" type="checkbox" style="width:auto" checked> レイヤー服</label>
<p><small>チェックしたカテゴリは、アバター一括保存では保存しません。下のボタンは、R2に保存済みのうちそのカテゴリのものを探します。</small></p>
<button id="sweepdry">R2を探索して不要物を一覧(削除はしない)</button>
<button id="sweepdel" hidden>見つかった不要物を削除</button>
<button id="cancel" hidden>中止</button>
<p><small>失敗(429・Robloxの5xx・通信エラー)は自動でやり直します(1件につき最大5回、間隔を空けて)。アバターのIDは上の「ユーザーID」欄を使います。</small></p>
<button id="copy">結果をコピー</button>
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
async function callUser(action){
  const o=$('out');o.hidden=false;o.textContent='送信中…';
  try{
    const r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passcode:$('pw').value,action:action,userId:$('uid').value})});
    o.textContent=JSON.stringify(await r.json(),null,2);
  }catch(e){o.textContent='通信に失敗しました';}
}
$('utest').onclick=()=>callUser('user');
$('avcmp').onclick=()=>callUser('avatar');
const sleepMs=(ms)=>new Promise((r)=>setTimeout(r,ms));
const TRIES=5;
let cancelled=false;
// 失敗してもやり直す価値があれば(retryable・通信エラー)、間隔を空けて最大TRIES回まで呼ぶ
async function adminCall(body,label,log){
  body.passcode=$('pw').value;
  let last={ok:false,error:'UNKNOWN'};
  for(let i=0;i<TRIES;i++){
    let wait=Math.min(1500*Math.pow(2,i),20000);
    try{
      const r=await fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      const j=await r.json().catch(()=>({ok:false,error:'BAD_RESPONSE'}));
      if(r.ok&&j.ok!==false)return j;
      last=j;
      if(!j.retryable)return j;
      if(j.retryAfter>0)wait=Math.min(j.retryAfter*1000,45000);
    }catch(e){last={ok:false,error:'NETWORK',retryable:true};}
    if(cancelled||i===TRIES-1)break;
    log(label+' → '+(last.error||'失敗')+(last.source?'('+last.source+')':'')+'。'+Math.round(wait/1000)+'秒後に再試行 ('+(i+2)+'/'+TRIES+')');
    await sleepMs(wait);
  }
  return last;
}
// IDを1件ずつ保存(順番に処理。429を避けるため並列にしない)
async function cacheAssets(ids,force,lines,render){
  let done=0,already=0,failed=[];
  for(let n=0;n<ids.length;n++){
    if(cancelled){lines.push('— 中止しました');break;}
    const id=ids[n];
    const head='['+(n+1)+'/'+ids.length+'] '+id;
    const j=await adminCall({action:'cache',assetId:id,force:force},head,(m)=>{lines.push('  '+m);render();});
    if(j.ok&&j.result==='already'){already++;lines.push(head+' = 既にR2にあり');}
    else if(j.ok){done++;lines.push(head+' ✓ 保存 ('+Math.round(j.size/1024)+'KB)');}
    else{failed.push(id);lines.push(head+' ✗ '+(j.error||'失敗')+(j.status?' ('+j.status+')':''));}
    render();
  }
  lines.push('');
  lines.push('完了: 保存 '+done+' / 既にあり '+already+' / 失敗 '+failed.length);
  if(failed.length)lines.push('失敗したID: '+failed.join(', '));
  render();
}
async function runCache(avatar){
  const o=$('out');o.hidden=false;cancelled=false;$('cancel').hidden=false;
  const lines=[];const render=()=>{o.textContent=lines.join('\\n');};
  const force=$('force').checked;
  try{
    let ids;
    if(avatar){
      const uid=$('uid').value.trim();
      lines.push('アバター取得中… (ユーザー '+uid+')');render();
      const a=await adminCall({action:'avatarCache',userId:uid,skip:skipList()},'アバター',(m)=>{lines.push('  '+m);render();});
      if(!a.ok){lines.push('✗ '+(a.error||'失敗'));render();return;}
      ids=a.assets.map((x)=>x.id);
      lines.push('アバター情報をR2に保存('+a.api+')。アセット '+ids.length+' 件を保存します');
      (a.skipped||[]).forEach((x)=>lines.push('  除外: '+x.id+' '+x.type+' '+x.name+' ['+x.category+']'));
      render();
    }else{
      ids=Array.from(new Set($('cids').value.split(/[^0-9]+/).filter(Boolean)));
      if(!ids.length){lines.push('アセットIDを入力してください');render();return;}
    }
    await cacheAssets(ids,force,lines,render);
  }catch(e){lines.push('エラー: '+e);render();}
  finally{$('cancel').hidden=true;}
}
const skipList=()=>['animation','layered'].filter((k)=>$('cat_'+k).checked);
// R2のasset/を30件ずつ調べる。dry=trueは一覧だけ、falseは見つかったものを削除
async function runSweep(dry){
  const cats=skipList();
  const o=$('out');o.hidden=false;
  if(!cats.length){o.textContent='カテゴリを1つ以上チェックしてください';return;}
  if(!dry&&!confirm('見つかった不要物をR2から削除します。よろしいですか?'))return;
  cancelled=false;$('cancel').hidden=false;$('sweepdel').hidden=true;
  const lines=[];const render=()=>{o.textContent=lines.join('\\n');};
  let cursor=null,scanned=0,found=0,unknown=0,deleted=0,bytes=0,ok=true;
  try{
    for(let page=1;;page++){
      if(cancelled){lines.push('— 中止しました');ok=false;break;}
      const j=await adminCall({action:'sweep',categories:cats,cursor:cursor,dryRun:dry},'探索 '+page,(m)=>{lines.push('  '+m);render();});
      if(!j.ok){lines.push('✗ '+(j.error||'失敗')+'(ここで止めました。もう一度押すと最初から調べ直します)');ok=false;break;}
      scanned+=j.scanned;unknown+=j.unknown.length;deleted+=j.deleted;
      j.matched.forEach((m)=>{found++;bytes+=m.size;lines.push((dry?'候補 ':'削除 ')+m.id+' ['+m.category+'] '+Math.round(m.size/1024)+'KB');});
      lines.push('… '+scanned+' 件調査済み');render();
      if(j.done)break;
      cursor=j.cursor;
    }
  }catch(e){lines.push('エラー: '+e);ok=false;}
  lines.push('');
  lines.push((dry?'候補 ':'削除 ')+found+' 件('+Math.round(bytes/1024)+'KB) / 調査 '+scanned+' 件 / 種別不明 '+unknown+' 件(不明は削除しません)');
  render();
  $('cancel').hidden=true;
  if(dry&&ok&&found>0)$('sweepdel').hidden=false;
}
$('sweepdry').onclick=()=>runSweep(true);
$('sweepdel').onclick=()=>runSweep(false);
$('cache').onclick=()=>runCache(false);
$('avcache').onclick=()=>runCache(true);
$('cancel').onclick=()=>{cancelled=true;};
$('copy').onclick=async()=>{try{await navigator.clipboard.writeText($('out').textContent);$('copy').textContent='コピーしました';}catch(e){$('copy').textContent='コピーできませんでした(長押しで選択してください)';}setTimeout(()=>{$('copy').textContent='結果をコピー';},2000);};
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

// 1回だけ呼んで、状態・所要時間・一部ヘッダ・本文をそのまま返す(診断用。再試行しない)
async function probe(url, init) {
  const t0 = Date.now();
  try {
    const r = await fetch(url, init);
    const text = await r.text();
    const headers = {};
    ['content-type', 'retry-after', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'cf-ray'].forEach((k) => { const v = r.headers.get(k); if (v) headers[k] = v; });
    let json = null;
    try { json = JSON.parse(text); } catch (e) { /* JSONでない */ }
    return { ok: r.ok, status: r.status, ms: Date.now() - t0, headers, json, body: json === null ? text.slice(0, TEST_BODY_CHARS) : undefined };
  } catch (e) {
    return { error: 'FETCH_FAILED' };
  }
}

const keysOf = (o) => (o && typeof o === 'object' && !Array.isArray(o) ? Object.keys(o).sort() : []);
const diffKeys = (a, b) => ({
  both: keysOf(a).filter((k) => keysOf(b).includes(k)),
  onlyV1: keysOf(a).filter((k) => !keysOf(b).includes(k)),
  onlyV4: keysOf(b).filter((k) => !keysOf(a).includes(k)),
});
const unionKeys = (list) => Array.from(new Set(list.flatMap((x) => keysOf(x)))).sort();
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// v1 と v4 のレスポンスの違いを要約する(エンジンが読む項目を中心に)
function compareAvatar(a, b) {
  const as1 = Array.isArray(a && a.assets) ? a.assets : [], as4 = Array.isArray(b && b.assets) ? b.assets : [];
  const ids1 = as1.map((x) => x && x.id), ids4 = as4.map((x) => x && x.id);
  const metaOf = (x) => (x && x.meta) || null;
  const byId4 = new Map(as4.map((x) => [x && x.id, x]));
  const metaDiff = as1
    .filter((x) => byId4.has(x && x.id) && !same(metaOf(x), metaOf(byId4.get(x.id))))
    .map((x) => ({ id: x.id, name: x.name, v1: metaOf(x), v4: metaOf(byId4.get(x.id)) }));
  return {
    topLevelKeys: diffKeys(a, b),
    playerAvatarType: { v1: a && a.playerAvatarType, v4: b && b.playerAvatarType, same: (a && a.playerAvatarType) === (b && b.playerAvatarType) },
    scales: { v1: a && a.scales, v4: b && b.scales, same: same(a && a.scales, b && b.scales) },
    bodyColors: {
      v1Keys: keysOf(a && (a.bodyColors || a.bodyColor3s)), v4Keys: keysOf(b && (b.bodyColors || b.bodyColor3s)),
      v1Field: a && (a.bodyColors ? 'bodyColors' : a.bodyColor3s ? 'bodyColor3s' : null), v4Field: b && (b.bodyColors ? 'bodyColors' : b.bodyColor3s ? 'bodyColor3s' : null),
      same: same(a && (a.bodyColors || a.bodyColor3s), b && (b.bodyColors || b.bodyColor3s)),
    },
    assets: {
      countV1: as1.length, countV4: as4.length,
      onlyV1: as1.filter((x) => !ids4.includes(x && x.id)).map((x) => ({ id: x.id, name: x.name })),
      onlyV4: as4.filter((x) => !ids1.includes(x && x.id)).map((x) => ({ id: x.id, name: x.name })),
      fieldKeysV1: unionKeys(as1), fieldKeysV4: unionKeys(as4),
      withMetaV1: as1.filter((x) => metaOf(x)).length, withMetaV4: as4.filter((x) => metaOf(x)).length,
      assetTypeKeysV1: unionKeys(as1.map((x) => x && x.assetType)), assetTypeKeysV4: unionKeys(as4.map((x) => x && x.assetType)),
      metaDifferences: metaDiff,
    },
  };
}

// ユーザー情報の診断: Open Cloud(キー付き)と、公開API(users.roblox.com)の応答を並べる
async function runUserTest(env, rawId) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ error: 'BAD_USER_ID' }, 400);
  const key = apiKeyOf(env);
  const out = { userId: id };
  out.openCloud = key
    ? await probe(USER_API + id, { headers: { 'x-api-key': key, Accept: 'application/json' } })
    : { error: 'NO_API_KEY' };
  out.publicApi = await probe('https://users.roblox.com/v1/users/' + id, { headers: { Accept: 'application/json' } });
  return adminJson(out, 200);
}

// アバター取得の比較: v1(非推奨)と v4 を同じユーザーで1回ずつ呼び、違いを要約して生のJSONも返す
async function runAvatarCompare(rawId) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ error: 'BAD_USER_ID' }, 400);
  const init = { headers: { Accept: 'application/json' } };
  const v1 = await probe('https://avatar.roblox.com/v1/users/' + id + '/avatar', init);
  const v4 = await probe('https://avatar.roblox.com/v4/avatar/users/' + id, init);
  const out = { userId: id };
  // v4は { avatarModel, avatarConfigurations } に包まれているので、中身を取り出して v1 と同じ階層で比べる
  const m4 = v4.json && v4.json.avatarModel && typeof v4.json.avatarModel === 'object' ? v4.json.avatarModel : null;
  out.summary = v1.json && v4.json
    ? { ...compareAvatar(v1.json, m4 || v4.json), v4Wrapper: m4 ? { unwrapped: 'avatarModel', otherTopLevelKeys: keysOf(v4.json).filter((k) => k !== 'avatarModel') } : null }
    : { note: '片方または両方のJSONが取れませんでした(statusを確認)', v1Status: v1.status, v4Status: v4.status };
  out.v1 = v1;
  out.v4 = v4;
  return adminJson(out, 200);
}

// ---- 管理ページからのキャッシュ保存(アセット / アバター) ----
// 管理ページ側が1アセットずつ呼び、失敗(retryable)は管理ページ側でも間隔を空けてやり直す。
// 1リクエストで1アセットだけ処理するので、Workerのsubrequest数やCPU時間の上限に当たりにくい。

// クライアントがやり直す価値のある失敗か(429・Roblox側5xx・通信エラー)。404/401/413などはやり直さない
const retryableFail = (res) => res.status === 429
  || ((res.error === 'UPSTREAM' || res.error === 'CDN') && !(res.upstreamStatus >= 400 && res.upstreamStatus < 500));
const failJson = (res) => adminJson({
  ok: false, error: res.error, status: res.upstreamStatus, source: res.source, retryAfter: res.retryAfter, retryable: retryableFail(res),
}, res.status);

// 1アセットをRobloxから取得してR2に保存(既にあれば force でなければ何もしない)
async function runCacheAsset(env, rawId, force) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ ok: false, error: 'BAD_ASSET_ID' }, 400);
  if (!env.ASSETS) return adminJson({ ok: false, error: 'NO_R2_BINDING' }, 503);
  const key = 'asset/' + id;
  if (!force) {
    try {
      const o = await env.ASSETS.head(key);
      if (o) return adminJson({ ok: true, id, result: 'already', size: o.size }, 200);
    } catch (e) { /* 確認に失敗しても取得は続ける */ }
  }
  const apiKey = apiKeyOf(env);
  if (!apiKey) return adminJson({ ok: false, error: 'NO_API_KEY' }, 503);

  const res = await fetchAsset(id, apiKey, maxBytesOf(env));
  if (!res.ok) return failJson(res);
  if (!res.storable) return adminJson({ ok: false, error: 'TOO_LARGE' }, 413);
  try {
    await env.ASSETS.put(key, res.buf, { httpMetadata: { contentType: res.type }, customMetadata: { fetchedAt: String(Date.now()) } });
  } catch (e) {
    return adminJson({ ok: false, error: 'R2_ERROR', retryable: true }, 500);
  }
  return adminJson({ ok: true, id, result: force ? 'refreshed' : 'cached', size: res.buf.byteLength, contentType: res.type }, 200);
}

// ---- カテゴリ除外 / 不要物の探索・削除 ----
// アセットの種別(AssetTypeId)でカテゴリを判定する。名前(例: RunAnimation)でも判定できる。
const CATEGORIES = {
  animation: { label: 'アニメーション・エモート', ids: [24, 48, 49, 50, 51, 52, 53, 54, 55, 56, 61], name: /Animation$/ },
  layered: { label: 'レイヤー服', ids: [64, 65, 66, 67, 68, 69, 70, 71, 72], name: /^(TShirt|Shirt|Pants|Jacket|Sweater|Shorts|LeftShoe|RightShoe|DressSkirt)Accessory$/ },
};
const TYPE_INDEX_KEY = 'index/asset-types.json'; // { "<assetId>": <assetTypeId>(0=不明) }。種別は変わらないので一度調べたら再取得しない
const ECONOMY_DETAILS_API = 'https://economy.roblox.com/v2/assets/';
const SWEEP_PAGE = 30; // 1回の探索で調べる件数(種別の問い合わせが外部subrequestの上限に当たらない数)

function categoryOf(typeId, typeName) {
  for (const [key, c] of Object.entries(CATEGORIES)) {
    if (c.ids.includes(Number(typeId)) || (typeName && c.name.test(typeName))) return key;
  }
  return null;
}
const validCategories = (v) => (Array.isArray(v) ? v.filter((k) => Object.prototype.hasOwnProperty.call(CATEGORIES, k)) : []);

async function loadTypes(env) {
  try {
    const o = await env.ASSETS.get(TYPE_INDEX_KEY);
    if (!o) return {};
    const j = JSON.parse(await o.text());
    return j && typeof j === 'object' ? j : {};
  } catch (e) { return {}; }
}
const saveTypes = (env, types) =>
  env.ASSETS.put(TYPE_INDEX_KEY, JSON.stringify(types), { httpMetadata: { contentType: 'application/json' } });

// 種別が分からないアセットを公開APIで調べる。戻り値: { ok: true, typeId } | { ok: false, res }
async function lookupAssetType(id) {
  try {
    const m = await fetchRetry(ECONOMY_DETAILS_API + id + '/details', { headers: { Accept: 'application/json' } });
    if (m.limited) return { ok: false, res: fail(429, 'RATE_LIMITED', m.limited) };
    if (!m.r.ok) return { ok: false, res: fail(m.r.status === 404 ? 404 : 502, m.r.status === 404 ? 'NOT_FOUND' : 'UPSTREAM', { upstreamStatus: m.r.status }) };
    const j = await m.r.json();
    const t = Number(j && (j.AssetTypeId != null ? j.AssetTypeId : j.assetTypeId));
    return Number.isFinite(t) && t > 0 ? { ok: true, typeId: t } : { ok: false, res: fail(502, 'NO_TYPE') };
  } catch (e) {
    return { ok: false, res: fail(502, 'UPSTREAM') };
  }
}

// R2の asset/ を30件ずつ調べ、選んだカテゴリのものを返す(dryRun でなければ削除もする)。cursor で続きから。
async function runSweep(env, b) {
  const cats = validCategories(b.categories);
  if (!cats.length) return adminJson({ ok: false, error: 'NO_CATEGORY' }, 400);
  if (!env.ASSETS) return adminJson({ ok: false, error: 'NO_R2_BINDING' }, 503);
  let l;
  try {
    l = await env.ASSETS.list({ prefix: 'asset/', limit: SWEEP_PAGE, cursor: typeof b.cursor === 'string' && b.cursor ? b.cursor : undefined });
  } catch (e) { return adminJson({ ok: false, error: 'R2_ERROR', retryable: true }, 500); }

  const types = await loadTypes(env);
  let dirty = false, stop = null;
  const matched = [], unknown = [];
  for (const o of l.objects) {
    const id = o.key.slice('asset/'.length);
    let t = types[id];
    if (t === undefined) {
      const r = await lookupAssetType(id);
      if (r.ok) { t = r.typeId; }
      else if (retryableFail(r.res)) { stop = r.res; break; }   // 続きは同じcursorでやり直す(調べ済みの分は保存される)
      else { t = 0; }                                            // 調べられない(削除済み等)は「不明」として残す
      types[id] = t; dirty = true;
    }
    const cat = t ? categoryOf(t, '') : null;
    if (!t) unknown.push(id);
    else if (cat && cats.includes(cat)) matched.push({ id, size: o.size, category: cat });
  }
  if (dirty) { try { await saveTypes(env, types); } catch (e) { /* 次回また調べるだけ */ } }
  if (stop) return failJson(stop);

  if (!b.dryRun && matched.length) {
    try { await env.ASSETS.delete(matched.map((m) => 'asset/' + m.id)); }
    catch (e) { return adminJson({ ok: false, error: 'R2_ERROR', retryable: true }, 500); }
  }
  return adminJson({
    ok: true, scanned: l.objects.length, matched, unknown, deleted: b.dryRun ? 0 : matched.length,
    cursor: l.truncated ? l.cursor : null, done: !l.truncated,
  }, 200);
}

// アバター情報を取得(v4 → だめなら v1。どちらも429/5xxはfetchRetryでやり直す)。戻り値: { ok, ver, text, assets }
async function fetchAvatar(id) {
  let err = fail(502, 'UPSTREAM');
  for (const [ver, url] of [['v4', 'https://avatar.roblox.com/v4/avatar/users/' + id], ['v1', 'https://avatar.roblox.com/v1/users/' + id + '/avatar']]) {
    try {
      const m = await fetchRetry(url, { headers: { Accept: 'application/json' } });
      if (m.limited) { err = fail(429, 'RATE_LIMITED', m.limited); continue; }
      if (m.r.status === 404) { err = fail(404, 'NOT_FOUND'); continue; }
      if (!m.r.ok) { err = fail(502, 'UPSTREAM', { upstreamStatus: m.r.status }); continue; }
      const text = await m.r.text();
      const j = JSON.parse(text);
      const model = j && j.avatarModel && typeof j.avatarModel === 'object' ? j.avatarModel : j; // v4は avatarModel に包まれている
      if (!model || !Array.isArray(model.assets)) { err = fail(502, 'NO_ASSETS'); continue; }
      const seen = new Set();
      const assets = [];
      for (const a of model.assets) {
        const aid = a && a.id != null ? String(a.id) : '';
        if (!/^\d{1,19}$/.test(aid) || seen.has(aid)) continue;
        seen.add(aid);
        const at = a && a.assetType;
        assets.push({ id: aid, name: (a && a.name) || '', type: (at && at.name) || '', typeId: at && Number(at.id) > 0 ? Number(at.id) : 0 });
      }
      return { ok: true, ver, text, assets };
    } catch (e) {
      err = fail(502, 'UPSTREAM');
    }
  }
  return err;
}

// アバター情報を取得して R2 (avatar/{userId}) に保存し、含まれるアセット一覧を返す(アセット本体の保存は管理ページが続けて行う)
async function runAvatarCache(env, rawId, rawSkip) {
  const id = String(rawId || '').trim();
  if (!/^\d{1,19}$/.test(id)) return adminJson({ ok: false, error: 'BAD_USER_ID' }, 400);
  if (!env.ASSETS) return adminJson({ ok: false, error: 'NO_R2_BINDING' }, 503);
  const res = await fetchAvatar(id);
  if (!res.ok) return failJson(res);
  try {
    await env.ASSETS.put('avatar/' + id, res.text, { httpMetadata: { contentType: 'application/json' }, customMetadata: { fetchedAt: String(Date.now()), api: res.ver } });
  } catch (e) {
    return adminJson({ ok: false, error: 'R2_ERROR', retryable: true }, 500);
  }
  // 種別を覚えておく(後の探索で再問い合わせしないため)。skip で選んだカテゴリは保存対象から外す
  const skip = validCategories(rawSkip);
  const assets = [], skipped = [];
  const types = await loadTypes(env);
  let dirty = false;
  for (const a of res.assets) {
    if (a.typeId && types[a.id] !== a.typeId) { types[a.id] = a.typeId; dirty = true; }
    const cat = categoryOf(a.typeId, a.type);
    if (cat && skip.includes(cat)) skipped.push({ id: a.id, name: a.name, type: a.type, category: cat });
    else assets.push(a);
  }
  if (dirty) { try { await saveTypes(env, types); } catch (e) { /* 無視 */ } }
  return adminJson({ ok: true, userId: id, api: res.ver, savedKey: 'avatar/' + id, assets, skipped }, 200);
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
  if (Number(req.headers.get('Content-Length')) > 8192) return adminJson({ error: 'TOO_LARGE' }, 413);

  let b;
  try { b = await req.json(); } catch (e) { b = {}; }
  const good = b && typeof b.passcode === 'string' && await safeEqual(b.passcode, String(env.ADMIN_PASSCODE));
  if (!good) {
    await sleep(1000); // 総当たりを遅くする(パスコードは長くすること)
    return adminJson({ error: 'BAD_PASSCODE' }, 401);
  }

  if (b.action === 'test') return runTest(env, b.assetId);
  if (b.action === 'usage') return runUsage(env);
  if (b.action === 'user') return runUserTest(env, b.userId);
  if (b.action === 'avatar') return runAvatarCompare(b.userId);
  if (b.action === 'cache') return runCacheAsset(env, b.assetId, b.force === true);
  if (b.action === 'avatarCache') return runAvatarCache(env, b.userId, b.skip);
  if (b.action === 'sweep') return runSweep(env, b);

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
