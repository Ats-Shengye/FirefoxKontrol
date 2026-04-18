# FirefoxKontrol

個人用途の軽量Firefox MV3拡張機能。CLIからローカルFirefoxのDOMを操作します。WebDriver BiDi / Marionette を起動せず、`geckodriver` を必要としない軽量ブリッジとして動作します。

[ChromeKontrol](https://github.com/Ats-Shengye/ChromeKontrol) のFirefox移植版。Firefox MV3 拡張機能 + Pythonサーバー構成で、WebSocket経由でCLIツールからFirefoxのDOMを操作します。

> **用途**: 開発・個人用途のローカルブラウザ制御を想定。Anti-bot検知回避や、スクレイピング検出回避を目的とした使用は意図していません。

## 対応ブラウザ

- Firefox 121以降（MV3 stable）

ChromeやEdgeでは動作しません（[ChromeKontrol](https://github.com/Ats-Shengye/ChromeKontrol) を使用）。

## クイックスタート

### 1. Python依存パッケージのインストール

```bash
pip install -r requirements.txt
```

### 2. 拡張機能の読み込み

**一時的（開発用）**:
1. `about:debugging#/runtime/this-firefox` を開く
2. 「一時的なアドオンを読み込む」で `manifest.json` を選択
3. Firefox再起動で消えるため、永続化したい場合は AMO 署名版を導入

**Flatpak版Firefoxの注意**:
拡張機能ファイルが `~/ドキュメント/` 等、Flatpak のデフォルト許可外パスに置かれていると、拡張機能の background.js ロードが失敗します。最小権限の観点から以下のいずれかを推奨:

```bash
# 推奨A: ~/ダウンロード/ (xdg-download) にコピーして読み込む
cp -r FirefoxKontrol ~/ダウンロード/
# about:debugging#/runtime/this-firefox から manifest.json を選択

# 推奨B: プロジェクト単体のみに権限を絞る
flatpak override --user --filesystem=/home/あなた/ドキュメント/Code/FirefoxKontrol org.mozilla.firefox
```

⚠ `--filesystem=xdg-documents` （ドキュメントフォルダ全体に権限付与）は**非推奨**。Firefox本体の脆弱性経由で被害範囲が広がるため、拡張機能ディレクトリのみを許可してください。

※ `:ro`（読み取り専用）指定だと Firefox MV3 の拡張機能 background.js 読み込みが失敗します（書き込み権限も必要）。

### 3. コマンド実行

```bash
echo '{"cmd":"get_dom"}' | python3 server.py
```

## コマンド一覧

| コマンド | フィールド | 説明 |
|---------|-----------|------|
| `get_dom` | `cmd` | アクティブタブのHTML全体を取得 |
| `click` | `cmd`, `selector` | CSSセレクタに一致する最初の要素をクリック |
| `get_elements` | `cmd`, `selector` | 一致する要素の情報（tag, text, href, id, class）を返す |

## サーブモード

```bash
python3 server.py --serve
```

起動時にstderrへ認証トークンが表示されます。HTTP APIへのアクセスには`X-FirefoxKontrol-Token`ヘッダーと`Content-Type: application/json`が必須です（CSRF対策）:

```bash
# トークンを固定する場合（~/.bashrc等に追加）
export FIREFOX_KONTROL_TOKEN=your_fixed_token_here

# サーバー起動
python3 server.py --serve
```

**環境変数でトークンを固定している場合**（stderrにトークン値は表示されません）:

```bash
# 環境変数がそのままヘッダー値として使えます
curl -s 127.0.0.1:9768 \
  -H "X-FirefoxKontrol-Token: $FIREFOX_KONTROL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"get_dom"}'

curl -s 127.0.0.1:9768 \
  -H "X-FirefoxKontrol-Token: $FIREFOX_KONTROL_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"get_elements","selector":"a","browser":"firefox"}'
```

**環境変数未設定の場合**（起動時にstderrへコピペ可能な形式で表示されます）:

```bash
# stderrに "TOKEN=xxx; curl ..." 形式で出力されるので、そのままコピペ可能
# 例: TOKEN=abc123...; curl -s 127.0.0.1:9768 -H "X-FirefoxKontrol-Token: $TOKEN" ...
TOKEN=<起動時のstderrから取得>
curl -s 127.0.0.1:9768 \
  -H "X-FirefoxKontrol-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"get_dom"}'
```

> **破壊的変更**: 認証ヘッダーなし、またはContent-Typeが`application/json`以外のリクエストはそれぞれ`401 Unauthorized` / `415 Unsupported Media Type`を返します。既存のcurlスクリプトへのヘッダー追加が必要です。

## ChromeKontrolとの共存

ポート番号がデフォルトで分離されているため、ChromeKontrol（9765/9766）と同時起動可能です。

| 拡張機能 | WebSocketポート | HTTPポート |
|---------|----------------|-----------|
| ChromeKontrol | 9765 | 9766 |
| FirefoxKontrol | 9767 | 9768 |

両方を同時に立ち上げて、Chrome/Edge/Firefoxを並行操作できます。

## 設定

| パラメータ | CLIフラグ | 環境変数 | デフォルト |
|-----------|----------|---------|-----------|
| WebSocket ポート | `--port` | `FIREFOX_KONTROL_PORT` | 9767 |
| HTTP API ポート | `--http-port` | `FIREFOX_KONTROL_HTTP_PORT` | 9768 |
| HTTP API 認証トークン | なし | `FIREFOX_KONTROL_TOKEN` | 起動ごとにランダム生成 |

## Firefox MV3 移植時に踏んだ地雷

Firefox MV3 は Chromium MV3 と挙動が異なる箇所があります。本拡張機能で対処済みの内容:

| 地雷 | 対処 |
|------|------|
| `background.service_worker` がデフォルト無効 | `background.scripts: ["background.js"]` 形式を使用 |
| `background.page` 形式が機能しない（HTMLは読まれるが script タグ評価されず） | `scripts` 形式を使用 |
| Flatpak版 Firefox で `xdg-documents:ro` だと拡張機能の background.js 読み込み失敗 | RW 権限が必須（README記載） |
| `ws://localhost` への接続が CSP 違反でブロック（Chrome MV3 は暗黙許可） | manifest に `content_security_policy.extension_pages` で `connect-src ws://127.0.0.1:9767` を明示 |

## ChromeKontrolとの差分

- **manifest.json**: `background.scripts` 方式（Event Page）。`browser_specific_settings.gecko` でID/最低バージョン指定。`content_security_policy.extension_pages` 明示
- **background.js**: `detectBrowser()` がFirefox専用、UA文字列ベース
- **server.py**: `ALLOWED_BROWSERS` は `firefox` のみ。`chrome-extension://` および素の `extension://` Origin拒否、`moz-extension://` を許可。デフォルトポート分離（9767/9768）
- **共通部分**: `content.js` はChromeKontrolと同一、`requirements.txt` も同一

## ライセンス

[MIT](LICENSE)
