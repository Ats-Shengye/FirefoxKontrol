# FirefoxKontrol 仕様書

## 概要

FirefoxKontrol は Firefox MV3 拡張機能とローカル WebSocket サーバーを介して、CLIツールからローカルFirefoxのDOMを操作する軽量ブリッジです。WebDriver BiDi / Marionette / geckodriver に依存しないため特別な起動フラグ不要で、開発・個人用途のスクリプト連携に向きます。

> **用途想定**: 個人環境のブラウザ自動化。Anti-bot検知回避やスクレイピング検出回避を目的とした使用は意図していません。

[ChromeKontrol](https://github.com/Ats-Shengye/ChromeKontrol) のFirefox移植版。共通部分はChromeKontrolと同じ実装で、ブラウザ固有の差分のみ持ちます。

## アーキテクチャ

```
CLIツール（stdin / curl）
        |
        v
  server.py（Python）
  - WebSocket サーバー（ポート 9767）
  - HTTP API サーバー（ポート 9768、サーブモード時のみ）
        |
        v  WebSocket（localhost限定）
        |
  background.js（MV3 Event Page）
  - WebSocket経由でコマンドを受信
  - executeCommand をアクティブタブに注入
  - 結果をサーバーに返却
        |
        v  chrome.scripting.executeScript（Firefox WebExtensions互換層）
        |
  ページコンテキスト（アクティブタブ）
  - DOM操作（get_dom, get_elements, click）
```

## 動作モード

### ワンショットモード（デフォルト）

```bash
echo '{"cmd":"get_dom"}' | python3 server.py
```

### サーブモード（`--serve`）

```bash
python3 server.py --serve
curl -s 127.0.0.1:9768 -d '{"cmd":"get_dom"}'
```

## コマンド一覧

| コマンド | フィールド | 説明 |
|---------|-----------|------|
| `get_dom` | `cmd` | アクティブタブの `outerHTML` 全体を返す。500KBで切り詰め、DOM要約を付加。 |
| `click` | `cmd`, `selector` | CSSセレクタに一致する最初の要素をクリック。 |
| `get_elements` | `cmd`, `selector` | 一致する要素の配列を返す（tag, text, href, id, className）。 |

`browser` フィールド省略可（接続が1つだけなら自動選択）。明示する場合は `"firefox"`。

### リクエスト形式

```json
{
  "cmd": "get_elements",
  "selector": "a.nav-link",
  "browser": "firefox"
}
```

### レスポンス形式

```json
{
  "result": "ok",
  "data": [...]
}
```

エラー時:

```json
{
  "result": "error",
  "message": "Element not found: .nonexistent"
}
```

## 接続モデル

拡張機能は接続直後に `identify` メッセージを送信:

```json
{"type": "identify", "browser": "firefox"}
```

- `firefox` 以外の `browser` 値は `ALLOWED_BROWSERS` で拒否される
- 既存接続がある状態で再接続が来た場合、古い接続は閉じられ新しい接続が登録される

## 設定

| パラメータ | CLIフラグ | 環境変数 | デフォルト |
|-----------|----------|---------|-----------|
| WebSocket ポート | `--port` | `FIREFOX_KONTROL_PORT` | 9767 |
| HTTP API ポート | `--http-port` | `FIREFOX_KONTROL_HTTP_PORT` | 9768 |

優先順位: CLIフラグ > 環境変数 > デフォルト値

## セキュリティモデル

### ネットワーク分離
- WebSocket / HTTP リスナーはともに `127.0.0.1` にのみバインド
- WebSocket の Origin ヘッダーを localhost 限定のホワイトリストで検証
- `moz-extension://` Origin を許可（Firefox拡張機能用）
- `chrome-extension://` Origin は明示的に拒否（Firefox専用版のため）

### 入力検証
- コマンドはホワイトリスト（`get_dom`, `click`, `get_elements`）で検証
- CSSセレクタは512文字上限
- ブラウザ名はホワイトリスト（`firefox`）で制限
- 受信メッセージは 5 MiB 上限

### 拡張機能 CSP
- manifest の `content_security_policy.extension_pages` で明示:
  `script-src 'self'; object-src 'self'; connect-src 'self' ws://127.0.0.1:9767`
- Firefox MV3 は Chrome MV3 と異なり ws://localhost を暗黙許可しないため明示必須
- カスタムポートを使う場合はmanifest側も合わせて修正が必要

### 出力サニタイズ
- ログメッセージは ASCII/Unicode 制御文字を除去
- ページコンテキストの生エラー詳細は呼び出し側に公開しない

### 拡張機能のセキュリティ
- `content.js` は意図的に空。DOM操作は `chrome.scripting.executeScript` で注入
- コマンド引数は関数パラメータとして渡す（コードインジェクション防止）

### HTTP サーバー
- POST のみ受け付け
- Content-Length 必須、上限あり
- ヘッダー読み取りは 8 KiB 上限、10秒デッドライン
- 並行リクエストは `asyncio.Lock` で直列化
- レスポンスヘッダーに `Cache-Control: no-store` および `X-Content-Type-Options: nosniff`

## Firefox MV3 Event Page のキープアライブ

Firefox の MV3 background は非永続な event page で動作します。Service Worker（Chromium）と異なりWebSocketオブジェクトを保持できるが、アイドル時にunloadされます。

1. `chrome.alarms`（クライアント側）: 30秒周期で event page を起こし、WebSocket が切断されていれば再接続
2. Ping フレーム（サーバー側、サーブモード）: サーバーが20秒間隔で WebSocket ping を送信

ChromeKontrolと同じ機構で、実機（Firefox 149）での識別・コマンド実行・再接続は確認済み。

## 依存関係

- Python: `websockets`（単一依存、`requirements.txt` でハッシュ固定）
- 拡張機能: 外部依存なし。Firefox WebExtensions API のネイティブ機能のみ

## ファイル構成

```
FirefoxKontrol/
  server.py         WebSocket/HTTP サーバー（Python）
  background.js     MV3 Event Page（拡張機能）
  content.js        コンテンツスクリプト（意図的に空、ChromeKontrolと同一）
  manifest.json     拡張機能マニフェスト（MV3 + browser_specific_settings.gecko）
  requirements.txt  Python 依存パッケージ（ChromeKontrolと同一、ハッシュ固定）
```
