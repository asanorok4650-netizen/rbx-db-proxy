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
- 許可IP: Workerの接続元はIPv6です。管理ページの診断テストの `egress.ip` を確認し、そのIP(例: `2a06:98c0:3600::103/128`)を許可してください。

## 注意

- **R2は無料枠を超えると自動で課金されます**(保存10GB、書き込み系100万回/月、読み取り系1,000万回/月が無料。最新は公式を確認)。管理ページの「使用量」を、たまに確認してください。
- Robloxのアセットを複製して保存してよいかは、Robloxの利用規約とアセットごとの権利に関わります。公開前に確認してください。
- 保存したアセットは自動では更新されません。Roblox側でアセットを更新した場合は、管理ページからキャッシュを削除してください。
- Robloxへの問い合わせの重複排除は、同じアイソレート内だけで効きます。
