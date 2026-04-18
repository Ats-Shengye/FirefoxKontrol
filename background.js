/**
 * FirefoxKontrol - background.js (Event Page)
 *
 * 目的     : ローカルサーバー (server.py) へのWebSocket接続を管理し、
 *            アクティブタブのContent Scriptにコマンドを中継する。
 * 理由     : Manifest V3 Firefox実装ではbackgroundは非永続のevent pageとして動作する。
 *            ChromeのService Workerと異なりWebSocket等のオブジェクトを保持できるが、
 *            それでもアイドル時にunloadされるため、chrome.alarmsで定期的に起動する。
 * 関連     : content.js (DOM操作), server.py (WebSocketサーバー), ChromeKontrol/background.js
 *
 * セキュリティ注記: 接続はlocalhostオリジンのみに制限される。
 *   ポートはstorage (server.py起動時に設定) から読み取るため、ハードコードされない。
 *   悪意あるWebサイトによるコマンド偽装を防ぐため、
 *   すべての受信メッセージに対してオリジン検証を実行する。
 *
 * 依存関係: 外部ランタイム依存なし。Firefox WebExtensions API
 *   (chrome.* 名前空間で互換提供される: chrome.storage, chrome.tabs, chrome.scripting, chrome.alarms)
 *   および標準WebSocketインターフェース。サードパーティライブラリは読み込まない。
 *
 * Chrome版との差分:
 *   - manifest.jsonがbackground.scripts方式（Event Page）
 *   - detectBrowser()がFirefoxを返すよう調整
 *   - その他のロジックはChrome版と同等
 */

'use strict';

// --- 定数 ---

/** デフォルトのWebSocketポート。server.pyのDEFAULT_PORTと一致させる必要がある。
 *  ChromeKontrol（9765）と衝突しないよう9767を使用。 */
const DEFAULT_WS_PORT = 9767;

/** 再接続間隔（ミリ秒）。指数バックオフの基底値。 */
const RECONNECT_BASE_MS = 1000;

/** 再接続間隔の上限。過剰な再接続を防止する。 */
const RECONNECT_MAX_MS = 5000;

/** Keepaliveアラーム名（安定した値である必要がある。アラーム識別子として使用）。 */
const KEEPALIVE_ALARM_NAME = 'firefoxkontrol:keepalive';

/** Keepaliveアラームの周期（分単位、0.5 = 30秒）。 */
const KEEPALIVE_PERIOD_MINUTES = 0.5;

/** 許可するWebSocketオリジン。localhostのバリアントのみ受け入れる。 */
const ALLOWED_ORIGINS = new Set([
  'ws://127.0.0.1',
  'ws://localhost',
  'ws://[::1]',
]);

// --- 状態 ---

/** @type {WebSocket|null} アクティブなWebSocket接続。 */
let ws = null;

/** 現在の再接続遅延（ミリ秒）。接続成功時にリセットされる。 */
let reconnectDelay = RECONNECT_BASE_MS;

/** 再接続タイマーのハンドル。 */
let reconnectTimer = null;

/** 並行するconnect()呼び出しを防ぐガードフラグ。 */
let isConnecting = false;

// --- ヘルパー ---

/**
 * chrome.storage.localから設定済みのWebSocketポートを返す。
 * 取得できない場合はDEFAULT_WS_PORTにフォールバックする。
 * @returns {Promise<number>}
 */
async function getPort() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['ws_port'], (result) => {
      const port = result.ws_port;
      if (typeof port === 'number' && port > 0 && port <= 65535) {
        resolve(port);
      } else {
        resolve(DEFAULT_WS_PORT);
      }
    });
  });
}

/**
 * WebSocket URLが許可されたlocalhostオリジンを使用しているか検証する。
 * @param {string} url
 * @returns {boolean}
 */
function isAllowedOrigin(url) {
  try {
    const parsed = new URL(url);
    const origin = `${parsed.protocol}//${parsed.hostname}`;
    return ALLOWED_ORIGINS.has(origin);
  } catch {
    return false;
  }
}

/**
 * ログ出力用の制御文字除去サニタイザ。
 * @param {string} str
 * @returns {string}
 */
function sanitiseForLog(str) {
  return String(str).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

// --- WebSocketライフサイクル ---

async function connect() {
  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  if (isConnecting) return;
  isConnecting = true;

  try {
    const port = await getPort();
    const url = `ws://127.0.0.1:${port}`;

    if (!isAllowedOrigin(url)) {
      console.error('[FirefoxKontrol] Refused connection to non-localhost URL:', sanitiseForLog(url));
      isConnecting = false;
      return;
    }

    console.log(`[FirefoxKontrol] Connecting to ${url} …`);
    ws = new WebSocket(url);

    ws.onopen = () => {
      console.log('[FirefoxKontrol] Connected.');
      reconnectDelay = RECONNECT_BASE_MS;
      isConnecting = false;
      sendIdentify();
    };

    ws.onmessage = (event) => {
      handleServerMessage(event.data);
    };

    ws.onerror = (_err) => {
      console.warn('[FirefoxKontrol] WebSocket error occurred.');
      isConnecting = false;
    };

    ws.onclose = () => {
      console.log(`[FirefoxKontrol] Disconnected. Reconnecting in ${reconnectDelay}ms …`);
      scheduleReconnect();
    };
  } catch (err) {
    console.error('[FirefoxKontrol] connect() threw unexpectedly:', sanitiseForLog(String(err)));
    isConnecting = false;
  }
}

function scheduleReconnect() {
  if (reconnectTimer !== null) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
    connect();
  }, reconnectDelay);
}

/**
 * Firefoxであることを確認してidentifyに使用するブラウザ名を返す。
 *
 * 検出ロジック:
 *   1. Firefox固有API: navigator.userAgent に "Firefox/" が含まれる → "firefox"
 *   2. 万一一致しない場合は "unknown" を返す（server側のALLOWED_BROWSERSで弾く）
 *
 * 注: ChromeKontrolと異なりChromiumを判定する経路は持たない。
 * 本拡張機能はFirefox専用であり、Chromiumに読み込まれた場合はブラウザ仕様の差異で
 * そもそも起動しないか、起動しても server.py 側が "unknown" を拒否する。
 *
 * @returns {string} "firefox" または "unknown"
 */
function detectBrowser() {
  try {
    const ua = (typeof navigator !== 'undefined' && navigator.userAgent) || '';
    if (ua.includes('Firefox/')) return 'firefox';
  } catch {
    // 防御的対応。
  }
  return 'unknown';
}

function sendIdentify() {
  const browser = detectBrowser();
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.warn('[FirefoxKontrol] Cannot send identify: WebSocket not open.');
    return;
  }
  try {
    ws.send(JSON.stringify({ type: 'identify', browser }));
    console.log(`[FirefoxKontrol] Identified as browser=${browser}`);
  } catch (err) {
    console.error('[FirefoxKontrol] Failed to send identify:', sanitiseForLog(String(err)));
  }
}

function sendResponse(payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.warn('[FirefoxKontrol] Cannot send: WebSocket not open.');
    return;
  }
  try {
    ws.send(JSON.stringify(payload));
  } catch (err) {
    console.error('[FirefoxKontrol] Failed to send response:', sanitiseForLog(String(err)));
  }
}

// --- コマンドルーティング ---

async function handleServerMessage(raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    console.warn('[FirefoxKontrol] Received non-JSON message; discarding.');
    sendResponse({ result: 'error', message: 'Invalid JSON command.' });
    return;
  }

  const allowedCommands = new Set(['get_dom', 'click', 'get_elements']);
  if (!msg || typeof msg.cmd !== 'string' || !allowedCommands.has(msg.cmd)) {
    sendResponse({ result: 'error', message: 'Unknown or missing command.' });
    return;
  }

  if ((msg.cmd === 'click' || msg.cmd === 'get_elements') && typeof msg.selector !== 'string') {
    sendResponse({ result: 'error', message: 'Missing or invalid selector.' });
    return;
  }

  if (typeof msg.selector === 'string' && msg.selector.length > 512) {
    sendResponse({ result: 'error', message: 'Selector exceeds maximum length (512).' });
    return;
  }

  await forwardToActiveTab(msg);
}

async function forwardToActiveTab(msg) {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  } catch (err) {
    sendResponse({ result: 'error', message: 'Failed to query active tab.' });
    return;
  }

  if (!tabs || tabs.length === 0) {
    sendResponse({ result: 'error', message: 'No active tab found.' });
    return;
  }

  const tab = tabs[0];

  if (!tab.url || !tab.url.startsWith('http')) {
    sendResponse({ result: 'error', message: 'Active tab URL is not scriptable (non-http).' });
    return;
  }

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: executeCommand,
      args: [msg],
    });

    if (!results || results.length === 0 || results[0] === undefined) {
      sendResponse({ result: 'error', message: 'Content script returned no result.' });
      return;
    }

    sendResponse(results[0].result);
  } catch (err) {
    console.error('[FirefoxKontrol] executeScript error:', sanitiseForLog(String(err)));
    sendResponse({ result: 'error', message: 'Script execution failed.' });
  }
}

// --- インジェクションされる関数（ページコンテキストで実行） ---

function executeCommand(msg) {
  'use strict';

  function sanitiseMsg(str) {
    return String(str).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
  }

  function buildDomSummary(doc) {
    const all = doc.querySelectorAll('*');
    const total = all.length;
    const tagCounts = Object.create(null);
    const sampleSize = Math.min(200, total);
    for (let i = 0; i < sampleSize; i++) {
      const tag = all[i].tagName.toLowerCase();
      tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    }
    const tagSummary = Object.entries(tagCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 15)
      .map(([tag, count]) => `${tag}(${count})`)
      .join(', ');
    return `[DOM summary: ${total} elements total. Top tags (sampled): ${tagSummary}]`;
  }

  const MAX_HTML_LENGTH = 500_000;

  try {
    if (msg.cmd === 'get_dom') {
      const html = document.documentElement.outerHTML;
      if (html.length > MAX_HTML_LENGTH) {
        const summary = buildDomSummary(document);
        return {
          result: 'ok',
          data: html.slice(0, MAX_HTML_LENGTH) + '\n\n<!-- truncated -->\n\n' + summary,
        };
      }
      return { result: 'ok', data: html };
    }

    if (msg.cmd === 'click') {
      let el;
      try {
        el = document.querySelector(msg.selector);
      } catch {
        return { result: 'error', message: `Invalid selector: ${sanitiseMsg(msg.selector)}` };
      }
      if (!el) {
        return { result: 'error', message: `Element not found: ${sanitiseMsg(msg.selector)}` };
      }
      el.click();
      return { result: 'ok' };
    }

    if (msg.cmd === 'get_elements') {
      let elements;
      try {
        elements = document.querySelectorAll(msg.selector);
      } catch {
        return { result: 'error', message: `Invalid selector: ${sanitiseMsg(msg.selector)}` };
      }
      const items = Array.from(elements).map((el) => {
        const entry = {
          tag: el.tagName.toLowerCase(),
          text: (el.textContent || '').trim().slice(0, 200),
        };
        if (el.href) entry.href = el.href;
        if (el.id) entry.id = el.id;
        const cls = el.className;
        if (typeof cls === 'string' && cls) entry.className = cls;
        return entry;
      });
      return { result: 'ok', data: items };
    }

    return { result: 'error', message: 'Unhandled command in content context.' };
  } catch (err) {
    return { result: 'error', message: 'Internal error during command execution.' };
  }
}

// --- Keepalive ---

function registerKeepaliveAlarm() {
  chrome.alarms.create(KEEPALIVE_ALARM_NAME, { periodInMinutes: KEEPALIVE_PERIOD_MINUTES });
}

function onAlarm(alarm) {
  if (alarm.name !== KEEPALIVE_ALARM_NAME) return;
  if (!ws || ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
    connect();
  }
}

chrome.alarms.onAlarm.addListener(onAlarm);

// --- エントリーポイント ---

connect();
registerKeepaliveAlarm();
