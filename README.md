# rbx-db-proxy

Robloxのアセットを、Cloudflare R2にキャッシュして返すプロキシ(Cloudflare Worker)。
一度取得したアセットはR2から返すので、Robloxへの問い合わせ(と429)が減ります。

## エンドポイント

| パス | 内容 |
|---|---|
| `GET /asset/{id}` | R2にあれば返す(`X-Cache: HIT`)。無ければRobloxから取得して保存し、返す(`MISS`)。R2未設定なら `BYPASS` |
| `GET /?url=...` | users / avatar の公開APIの中継(キー無し。許可したものだけ) |
| `GET /health` | 接続確認 |
| `GET /` | 管理ページ(パスコード式) |

管理ページでできること: 診断テスト(キー・接続元IP・Robloxの応答をそのまま表示)、キャッシュの有無確認、キャッシュ削除、R2使用量の確認。

## エンドポイント `GET /user/{id}`

Open Cloud(`GET /cloud/v2/users/{id}`)をAPIキーで呼び、`{ id, name, displayName }` を返します。結果はR2に1日キャッシュします(`X-Cache: HIT|MISS|BYPASS`)。公開API(`users.roblox.com`)の中継より、キー単位の枠(1000回/分)で動くので429になりにくいです。`/health` の `version` が 2 以上、`userApi: true` なら対応済みです。

## 管理ページのユーザー/アバター取得テスト

管理ページ(`/`)の「ユーザー / アバター取得テスト」で、ユーザーID(数字)を入れて使います(パスコードが必要)。
- **ユーザー情報(Open Cloud)を取得**: `/cloud/v2/users/{id}`(APIキー)と `users.roblox.com/v1/users/{id}`(公開API)を1回ずつ呼び、status・所要時間・応答を並べます。キーの権限(`user.advanced:read`)の確認にも使えます。
- **アバター v1 と v4 を比較**: `avatar.roblox.com/v1/users/{id}/avatar`(非推奨)と `/v4/avatar/users/{id}` を1回ずつ呼び、違い(項目名・アセットの増減・`meta`の差・スケール・体色の項目)の要約と、それぞれの生JSONを返します。「結果をコピー」で全文をコピーできます。
- 診断のため再試行しません(429が出たらそのまま見えます)。`?url=` の中継では `/v4/avatar/users/{id}` も許可しています。

## 管理ページからのキャッシュ保存

管理ページ(`/`)の「Robloxから読み込んでR2に保存」で使います(パスコードが必要)。
- **アセットを取得してR2に保存**: アセットIDを入力(カンマ・空白区切りで複数可)。R2に既にあるものはスキップします。「既にR2にあっても取り直す」で上書き。
- **アバターを取得して、含まれるアセットごとR2に保存**: 上の「ユーザーID」欄を使います。アバター情報(v4、だめならv1)を `avatar/{userId}` に保存し、含まれるアセットを1件ずつ `asset/{id}` に保存します。
- **リトライ**: Worker内で429・Robloxの5xx・通信エラーを最大3回、管理ページ側でも失敗(retryable)を最大5回、間隔を空けてやり直します(429の `Retry-After` を尊重)。404・キー拒否・サイズ超過などはやり直しません。
- 1アセットずつ別リクエストで処理するので、Workerのsubrequest数・CPU時間の上限に当たりにくく、途中で「中止」もできます。失敗したIDは最後に一覧表示します。
- R2の書き込みが1件ごとに発生します(無料枠の書き込み回数に注意)。

## 429の見分け(応答の `source`)

| source | 意味 |
|---|---|
| `worker-request` / `worker-upstream` | このWorkerのレート制限 |
| `roblox-edge` | Roblox手前のCloudflareの制限(`error code: 1015`)。Workerの共有IPの混雑が原因の可能性 |
| `roblox` | Roblox側(APIキー)の制限 |

Robloxへの問い合わせは、29のときWorker内で間隔を空けて3回までやり直します。

## セットアップ(スマホのブラウザだけでできます)

1. **R2バケットを作る**: Cloudflareダッシュボード → R2 → バケットを作成。名前は `rbx-assets`(`wrangler.toml` と同じにする)。R2の有効化時に支払い方法の登録を求められることがあります。
2. **Workerを作る**: Workers & Pages → 作成 → GitHubをインポート → このリポジトリ。ビルドコマンドは空欄、デプロイコマンドは `npx wrangler deploy`。
3. **シークレットを設定**: Workerの「設定」→「変数とシークレット」(**ランタイム側**。ビルド側ではありません)で、種類を「シークレット」にして追加。
   - `ROBLOX_API_KEY`: Open CloudのAPIキー
   - `ADMIN_PASSCODE`: 管理ページのパスコード(16文字以上推奨)
   - `CF_API_TOKEN`(任意): 使用量表示用。CloudflareのAPIトークンで、権限は Account Analytics の読み取り
4. **`wrangler.toml` を編集**: `ALLOWED_ORIGIN`(ビューアのOrigin)と、使用量表示を使うなら `CF_ACCOUNT_ID` を設定。
5. Workerの `/health` を開いて `hasApiKey` と `hasCache` が `true` になっていることを確認し、管理ページ(`/`)で診断テスト。

### APIキーの作り方(Creator Hub)

- 権限: `legacy-asset:manage`
- 権限(追加): `user.advanced:read`(Users API の読み取り)。`GET /user/{id}`(表示名の取得)に使います。無くてもアバター読み込みは動きますが、表示名の代わりにIDが表示されます。
- キーを作り直したら、Workerの `ROBLOX_API_KEY` を更新してください。
- 許可IP: Workerの接続元はIPv6です。管理ページの診断テストの `egress.ip` を確認し、そのIP(例: `2a06:98c0:3600::103/128`)を許可してください。

## 注意

- **R2は無料枠を超えると自動で課金されます**(保存10GB、書き込み系100万回/月、読み取り系1,000万回/月が無料。最新は公式を確認)。管理ページの「使用量」を、たまに確認してください。
- Robloxのアセットを複製して保存してよいかは、Robloxの利用規約とアセットごとの権利に関わります。公開前に確認してください。
- 保存したアセットは自動では更新されません。Roblox側でアセットを更新した場合は、管理ページからキャッシュを削除してください。
- Robloxへの問い合わせの重複排除は、同じアイソレート内だけで効きます。
