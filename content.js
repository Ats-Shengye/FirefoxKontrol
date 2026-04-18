/**
 * FirefoxKontrol - content.js (Content Script)
 *
 * 目的     : すべてのページコンテキストに読み込まれる薄いシム。
 *            現在のアーキテクチャでは、実際のDOM操作はbackground.jsの
 *            chrome.scripting.executeScript経由でインジェクトされる関数
 *            (executeCommand) によって実行される。将来のユースケース
 *            （例: 永続的なDOM変更の監視）をmanifest変更なしで追加できるよう
 *            このファイルを保持している。
 * 理由     : Manifest V3のContent Scriptは隔離されたワールドで実行される。
 *            Content Scriptのフットプリントを最小限に保ち、不要なページコンテキスト
 *            への露出を避けるため、重いロジックはbackground.jsに置く。
 * 関連     : background.js (コマンドルーティングとインジェクション)
 *
 * セキュリティ注記: このファイルは意図的にDOMアクセスもネットワーク呼び出しも行わない。
 *   侵害されたContent Scriptの影響範囲を限定するため、すべてのコマンド実行は
 *   background.jsのインジェクトされたexecuteCommand関数を通じて行われる。
 */

'use strict';

// 意図的に空にしている。
// DOM操作はbackground.jsのchrome.scripting.executeScript経由で処理される。
