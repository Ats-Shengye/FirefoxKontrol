# FirefoxKontrol 用語集

本プロジェクトで使用する技術用語・概念の一覧。
コードリーディングの補助資料として使用。

updated: 2026-04-18

## 基本用語

| 用語 | 説明 |
| --- | --- |
| WebDriver BiDi / Marionette | Firefox の標準的なリモート制御プロトコル。geckodriver 経由で利用。`navigator.webdriver = true` がセットされ Anti-bot 検知対象。FirefoxKontrol は使用しない |
| MV3（Manifest V3） | Firefox 109+ で stable サポートされた拡張機能プラットフォーム。`background.scripts`（event page、非永続）が標準形式 |
| Event Page | MV3 Firefox の background スクリプト形式。Chromium の Service Worker と異なり WebSocket 等を保持できるが、アイドル時に unload される |
| コンテンツスクリプト | 拡張機能から Web ページに注入されるスクリプト。ページ JS とは隔離された Isolated World で動作。FirefoxKontrol の `content.js` は意図的に空 |

## WebExtensions API

| API | 説明 |
| --- | --- |
| `chrome.scripting.executeScript` | タブのページコンテキストに関数を注入する API。`browser.*` 名前空間のエイリアス。デバッグモード不要、画面上のインジケーターなし。FirefoxKontrol の DOM アクセスの中核 |
| `chrome.alarms` | 定期タイマー API。Event Page が unload されても発火するため、キープアライブに利用（30秒周期） |
| `chrome.storage.local` | 拡張機能ローカルストレージ。WebSocket ポート番号の永続化に使用 |

## 動作モード

| モード | 説明 |
| --- | --- |
| ワンショットモード | デフォルト。stdin から JSON コマンドを1つ読み取り、拡張機能に転送、stdout にレスポンス出力して終了 |
| サーブモード（`--serve`） | 常駐動作。HTTP API（デフォルト 9768）で POST 受付。起動レイテンシなしで連続コマンド実行に対応 |

## プロトコル

| 用語 | 説明 |
| --- | --- |
| Identify ハンドシェイク | 接続時の初期メッセージ交換。拡張機能が WebSocket 接続直後に `{"type": "identify", "browser": "firefox"}` を送信し、サーバーがブラウザ名で接続を登録 |

## コマンド一覧

| コマンド | フィールド | 説明 |
| --- | --- | --- |
| `get_dom` | `cmd` | アクティブタブの `outerHTML` 全体を返す。500KB超で切り詰め + DOM要約付加 |
| `click` | `cmd`, `selector` | CSS セレクタに一致する最初の要素をクリック |
| `get_elements` | `cmd`, `selector` | 一致する要素の情報（tag, text, href, id, className）を配列で返す |

## ファイル構成

| ファイル | 役割 |
| --- | --- |
| `server.py` | WebSocket / HTTP サーバー（Python）。ワンショット / サーブ両対応 |
| `background.js` | MV3 Event Page。WebSocket 中継 + コマンドルーティング + DOM操作注入 |
| `content.js` | コンテンツスクリプト（意図的に空。DOM操作は `executeScript` で注入） |
| `manifest.json` | 拡張機能マニフェスト（MV3 + `browser_specific_settings.gecko`） |
| `requirements.txt` | Python 依存パッケージ（`websockets`、ハッシュ固定） |

## Firefox MV3 固有の地雷

| 項目 | 詳細 |
| --- | --- |
| `background.service_worker` 不可 | Firefox 149時点で `extensions.backgroundServiceWorker.enabled` がデフォルト false。`scripts` 形式が標準 |
| `background.page` 機能不全 | HTML は読み込まれる（Quirks Mode警告は出る）が内部 `<script>` タグが評価されない。`scripts` 形式を使うこと |
| Flatpak版で `xdg-documents:ro` NG | Firefox MV3 の background.js 読み込みが失敗する。`flatpak override --user --filesystem=xdg-documents` (RW) 必須 |
| CSP `connect-src` 明示必須 | Chrome MV3 と異なり `ws://localhost` を暗黙許可しない。`content_security_policy.extension_pages` で `connect-src ws://127.0.0.1:9767` を明示 |

## セキュリティ対策

| 項目 | 実装 |
| --- | --- |
| ネットワーク分離 | WebSocket / HTTP ともに `127.0.0.1` にのみバインド |
| Origin 検証 | WebSocket ハンドシェイク時に localhost + `moz-extension://` 限定ホワイトリストで検証 |
| CSRF トークン認証 | HTTP API リクエストに `X-FirefoxKontrol-Token` ヘッダーを必須化。`secrets.compare_digest()` でタイミング攻撃対策。環境変数 `FIREFOX_KONTROL_TOKEN` で固定可能（未設定時はランダム生成） |
| Content-Type 強制 | `Content-Type: application/json` を必須化し CORS preflight を強制。simple request による CSRF 攻撃を防止 |
| コマンドホワイトリスト | `get_dom` / `click` / `get_elements` のみ受付 |
| セレクタ長制限 | CSS セレクタ 512 文字上限 |
| ブラウザ名制限 | `firefox` のみホワイトリストで制限 |
| メッセージサイズ制限 | 受信 5 MiB 上限でメモリ枯渇防止（GHSA-6g87-ff9q-v847 対策） |
| ログインジェクション防止 | ASCII / Unicode 制御文字を除去してログ出力 |
| コードインジェクション防止 | コマンド引数は関数パラメータとして渡し、文字列結合を回避 |
| HTTP ヘッダー制限 | 8 KiB 上限 + 10秒デッドライン |
| 並行リクエスト直列化 | `asyncio.Lock` でレスポンス混入を防止 |
| レスポンスヘッダー | `Cache-Control: no-store` + `X-Content-Type-Options: nosniff` |
| 拡張機能 CSP | `script-src 'self'; object-src 'self'; connect-src 'self' ws://127.0.0.1:9767` |

## 新規定数（CSRF対策）

| 定数 | 値 | 説明 |
| --- | --- | --- |
| `HTTP_AUTH_HEADER_NAME` | `X-FirefoxKontrol-Token` | HTTP API CSRF 対策トークンのヘッダー名。`secrets.compare_digest()` で検証。値はログに記録しない |
| `REQUIRED_CONTENT_TYPE` | `application/json` | HTTP API の必須 Content-Type。CORS preflight を強制するために検証 |
