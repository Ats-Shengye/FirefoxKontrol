"""
Location   : FirefoxKontrol/server.py
Purpose    : CLIツール（Bash, curl等）とFirefoxKontrol拡張機能を橋渡しする
             WebSocketサーバー。2つのモードに対応:
               - ワンショットモード（デフォルト）: stdinからコマンドを1つ読み取り、
                 拡張機能に送信し、レスポンスを出力して終了。
               - サーブモード（--serve）: 無期限に稼働し、ポート9768のHTTPリスナーが
                 POSTリクエストを受け付け、WebSocket経由で拡張機能に転送する。
Why        : Firefox側のリモート制御手段（WebDriver BiDi / Marionette）は別経路で重い。
             軽量なローカルWebSocketサーバーで localhost 限定を維持しつつ、
             拡張機能経由の chrome.scripting.executeScript で DOM 操作する。
             常駐サーブモードにより、連続実行時の起動レイテンシを解消する。
Related    : background.js (client), manifest.json
             ChromeKontrol (Chrome/Edge版): https://github.com/Ats-Shengye/ChromeKontrol

接続モデル:
  - FirefoxKontrol拡張機能（Firefox）が接続。
  - 拡張機能は接続直後にidentifyメッセージを送信する:
      {"type": "identify", "browser": "firefox"}
  - コマンドは "browser":"firefox" を指定可能。省略時は唯一の接続を自動使用。

ChromeKontrolとの共存:
  - デフォルトポートは9767/9768（ChromeKontrolは9765/9766）。
    両方を同時起動しても衝突しない。

セキュリティ上の考慮事項:
  - WebSocketとHTTPの両リスナーは127.0.0.1にのみバインドする。
  - WebSocket接続時にlocalhostのOriginヘッダーを検証する。
  - 受信メッセージサイズを制限しメモリ枯渇を防止する（GHSA-6g87-ff9q-v847）。
  - 受信HTTPおよびWebSocketコマンドの構造バリデーションを実施する。
  - 同時HTTPリクエストはasyncio.Lockで直列化し、同時呼び出し間の
    レスポンスの混在を防止する。
  - HTTPリクエストにはX-FirefoxKontrol-Tokenヘッダーによるトークン認証を必須とする。
    CSRFのsimple request（preflight不要）攻撃を防止する。
  - HTTPリクエストにはContent-Type: application/jsonを必須とし、CORS preflightを強制する。
  - 機密データはログに記録しない。トークン値はログ・エラーレスポンスに含めない。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import unicodedata
from typing import Any

import websockets
import websockets.server

# ---------------------------------------------------------------------------
# ログ設定
# ---------------------------------------------------------------------------

# 設計判断: ロガーをモジュールレベルで設定することで、外部の呼び出し元
# （テストランナー等）がこのファイルを変更せずにハンドラーを上書きできるようにしている。
logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """CLI使用時のルートロガーを設定する。

    Coding.mdのLogging Layer Design原則に従い、ハンドラーの設定は
    エントリーポイント関数に限定している。
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# 定数
# ---------------------------------------------------------------------------

DEFAULT_PORT: int = 9767
DEFAULT_HTTP_PORT: int = 9768
BIND_HOST: str = '127.0.0.1'

# 単一の受信WebSocketメッセージの最大バイト長。
# GHSA-6g87-ff9q-v847（大きなメッセージによるメモリ枯渇）を緩和する。
# 5 MBは一般的なページのDOM HTMLに対して十分な余裕がありつつ、上限を設ける。
MAX_MESSAGE_BYTES: int = 5 * 1024 * 1024  # 5 MiB

# このサーバーが受け付けるコマンド（background.jsでも同じセットをバリデーション）。
ALLOWED_COMMANDS: frozenset[str] = frozenset({'get_dom', 'click', 'get_elements'})

# セレクター長の上限（background.jsのバリデーションと同一）。
MAX_SELECTOR_LENGTH: int = 512

# このサーバーが受け付けるブラウザ名。identifyメッセージの "browser" フィールドが
# このセットに含まれない場合は拒否し、予期しないクライアントが任意の名前で
# 登録するのを防ぐ。
ALLOWED_BROWSERS: frozenset[str] = frozenset({'firefox'})

# ローカル以外の接続を防ぐための許可済みlocalhostオリジン値。
ALLOWED_ORIGINS: frozenset[str] = frozenset({
    f'ws://{BIND_HOST}',
    'ws://localhost',
    'ws://127.0.0.1',
})
# 注: 'null' オリジン（file:// ページ由来）は _is_allowed_origin() で明示的に拒否する。

# CSRF対策: HTTPリクエスト認証に使用するカスタムヘッダー名。
# ブラウザのsimple request判定（preflightなし）を回避するため、
# カスタムヘッダーを必須とする。これによりCORS preflightが強制される。
# セキュリティ注記: ヘッダー名はログに記録してよいが、ヘッダー値（トークン）は絶対に記録しない。
HTTP_AUTH_HEADER_NAME: str = 'X-FirefoxKontrol-Token'

# CSRF対策: Content-Type検証。application/json以外を拒否することで
# CORS preflightを強制し、simple requestによる攻撃を防止する。
REQUIRED_CONTENT_TYPE: str = 'application/json'


# ---------------------------------------------------------------------------
# 入力バリデーション
# ---------------------------------------------------------------------------

def _sanitise_for_log(value: Any) -> str:
    """ログ出力前に値からASCIおよびUnicode制御文字を除去する。

    悪意のあるペイロードが改行、エスケープシーケンス、Unicode制御文字
    （例: U+202E RIGHT-TO-LEFT OVERRIDE, U+FEFF BOM, U+2028 LINE SEPARATOR）を
    埋め込んでログエントリを偽造したりターミナル表示を操作するログインジェクション攻撃を防止する。

    Unicodeカテゴリによるフィルタリング:
      - 'Cf' (Format): 不可視の書式制御文字（U+202E, U+FEFF等）
      - 'Cc' (Control): C0/C1制御コード（改行、エスケープ等）
      - 'Cs' (Surrogate): エンコードエラーを引き起こす孤立サロゲート

    Args:
        value: サニタイズ対象の任意の値。

    Returns:
        全ての制御文字/書式文字を除去したサニタイズ済み文字列表現。
    """
    raw = str(value)
    return ''.join(
        ch for ch in raw
        if (ch >= ' ' or ch == '\t') and unicodedata.category(ch) not in ('Cf', 'Cc', 'Cs')
    )


def _validate_command(msg: Any) -> tuple[bool, str]:
    """CLI呼び出し元からのパース済みコマンドdictをバリデーションする。

    Args:
        msg: パース済みJSON値（dictであることを期待）。

    Returns:
        (is_valid, error_message) のタプル。
        is_validがTrueの場合、error_messageは空文字列。
    """
    if not isinstance(msg, dict):
        return False, 'Command must be a JSON object.'

    cmd = msg.get('cmd')
    if not isinstance(cmd, str) or cmd not in ALLOWED_COMMANDS:
        return False, f'Unknown or missing command: {_sanitise_for_log(cmd)}'

    selector = msg.get('selector')
    if cmd in ('click', 'get_elements'):
        if not isinstance(selector, str):
            return False, 'Missing or invalid selector field.'
        if len(selector) > MAX_SELECTOR_LENGTH:
            return False, f'Selector exceeds maximum length ({MAX_SELECTOR_LENGTH}).'

    # オプションのbrowserフィールド: 存在する場合は許可リスト内の文字列であること。
    browser = msg.get('browser')
    if browser is not None:
        if not isinstance(browser, str):
            return False, 'browser field must be a string.'
        if browser not in ALLOWED_BROWSERS:
            return False, f'Unknown browser: {_sanitise_for_log(browser)}'

    return True, ''


# ---------------------------------------------------------------------------
# Originバリデーション
# ---------------------------------------------------------------------------

def _is_allowed_origin(headers: Any) -> bool:
    """WebSocketハンドシェイクのOriginがlocalhostであることを確認する。

    websockets 10.x はヘッダーを .get() メソッドを持つHeadersオブジェクトとして公開する。

    設計判断: Originヘッダーの欠如をチェックするのではなく、ホワイトリストと
    大文字小文字を区別せず比較する。これにより、常にOriginを送信するブラウザが
    非localhostの値で偽装されることを防ぐ。

    Args:
        headers: WebSocketハンドシェイクのリクエストヘッダー。

    Returns:
        Originが許容されるlocalhostバリアントの場合True。
    """
    origin: str = (headers.get('Origin') or '').lower()
    # "null" オリジン（file://等からのシリアライズ済みオリジン）を拒否する。
    if origin == 'null':
        return False
    # Originヘッダーなしの接続を許可する（wscat等のCLIツール用）。
    if not origin:
        return True
    # Firefox拡張機能のオリジンを許可する（moz-extension:// 形式）。
    # サーバーは127.0.0.1にのみバインドしているため、ローカルの拡張機能
    # だけがこのポートに到達できる。
    if origin.startswith('moz-extension://'):
        return True
    allowed_lower = {o.lower() for o in ALLOWED_ORIGINS if o != 'null'}
    return origin in allowed_lower


# ---------------------------------------------------------------------------
# サーバーハンドラー
# ---------------------------------------------------------------------------

class FirefoxKontrolServer:
    """マルチクライアントWebSocketサーバー。

    ブラウザ名（"firefox"）の接続済み拡張機能クライアントを管理する。
    CLI呼び出し元はコマンドを送信し、リクエストごとに1つのレスポンスを受け取る。
    コマンド内のオプション "browser" フィールドで対象クライアントを選択する。
    省略時にクライアントが1つだけ接続されていればそれを自動使用する。

    接続ライフサイクル:
      1. 拡張機能がWebSocket経由で接続する。
      2. 拡張機能が即座に {"type": "identify", "browser": "<name>"} を送信する。
      3. サーバーがそのブラウザ名でクライアントを登録する。
      4. 以降のそのソケットからのメッセージはコマンドレスポンスとして扱われる。

    スレッドセーフティに関する注意: asyncioはイベントループ内でシングルスレッドのため、
    _clientsと_pending_responseへのアクセスにロックは不要。
    _command_lockは同時HTTPリクエストを直列化し、WebSocketラウンドトリップが
    一度に1つだけ実行されるようにし、レスポンスの混在を防止する。
    """

    # 新規接続後にidentifyメッセージを待つ最大秒数。
    # 3秒は正規のローカル拡張機能には十分であり、それ以上は遅延または
    # 悪意のあるクライアントのために接続スロットを不必要に開けておくことになる。
    _IDENTIFY_TIMEOUT: float = 3.0

    def __init__(self) -> None:
        # ブラウザ名 -> アクティブなWebSocketServerProtocolのマッピング。
        self._clients: dict[str, websockets.server.WebSocketServerProtocol] = {}
        self._response_event: asyncio.Event = asyncio.Event()
        self._pending_response: dict[str, Any] | None = None
        # 設計判断: 全ての同時呼び出し元が同じイベントループ内で動作するため、
        # threading.LockではなくasyncioのLockを使用する。このロックにより
        # 一度に1つのHTTPリクエストだけがWebSocketラウンドトリップを占有し、
        # 最初の呼び出し元がレスポンスを読む前に2番目の呼び出し元が
        # _response_event / _pending_responseを上書きすることを防ぐ。
        self._command_lock: asyncio.Lock = asyncio.Lock()

    async def handle_connection(
        self,
        websocket: websockets.server.WebSocketServerProtocol,
    ) -> None:
        """ブラウザ拡張機能からの受信WebSocket接続を処理する。

        identifyメッセージを待ち、報告されたブラウザ名でクライアントを登録し、
        ソケットが閉じるまで後続のコマンドレスポンスメッセージを処理する。

        Args:
            websocket: 接続済みクライアントのプロトコルオブジェクト。
        """
        # 接続境界でのOriginバリデーション。
        if not _is_allowed_origin(websocket.request_headers):
            logger.warning(
                'Rejected connection from non-localhost origin: %s',
                _sanitise_for_log(websocket.request_headers.get('Origin', '<none>')),
            )
            await websocket.close(code=1008, reason='Forbidden origin')
            return

        # 最初のメッセージとしてidentifyメッセージを期待する。
        browser_name = await self._receive_identify(websocket)
        if browser_name is None:
            # _receive_identifyが既に適切な理由でソケットを閉じている。
            return

        # このブラウザの既存接続が登録されている場合、古い接続を閉じて
        # 新しい接続に置き換える（例: ブラウザが拡張機能を再起動した場合）。
        old_client = self._clients.get(browser_name)
        if old_client is not None:
            logger.info(
                'Replacing existing %s connection with new one.',
                _sanitise_for_log(browser_name),
            )
            try:
                await old_client.close(code=1001, reason='Replaced by new connection')
            except Exception:
                pass  # ベストエフォートでの切断。新しい接続が無条件で引き継ぐ。

        self._clients[browser_name] = websocket
        logger.info('Extension connected: browser=%s', _sanitise_for_log(browser_name))

        try:
            async for raw_message in websocket:
                await self._handle_message(raw_message)
        except websockets.exceptions.ConnectionClosedOK:
            logger.info('Extension disconnected normally: browser=%s', _sanitise_for_log(browser_name))
        except websockets.exceptions.ConnectionClosedError as exc:
            logger.warning(
                'Extension disconnected with error: browser=%s error=%s',
                _sanitise_for_log(browser_name),
                _sanitise_for_log(exc),
            )
        finally:
            # このwebsocketオブジェクトのみ削除する。代替が既に登録されている可能性がある。
            if self._clients.get(browser_name) is websocket:
                del self._clients[browser_name]
            # コマンド待機中のタスクをアンブロックし、切断を検知できるようにする。
            self._response_event.set()
            logger.info('Extension connection cleaned up: browser=%s', _sanitise_for_log(browser_name))

    async def _receive_identify(
        self,
        websocket: websockets.server.WebSocketServerProtocol,
    ) -> str | None:
        """新規接続からの初期identifyメッセージを待機しバリデーションする。

        Args:
            websocket: 新たに受け入れたWebSocket接続。

        Returns:
            成功時はブラウザ名文字列（"firefox"）、
            接続が拒否された場合はNone（その場合ソケットは既に閉じられている）。
        """
        try:
            raw = await asyncio.wait_for(websocket.recv(), timeout=self._IDENTIFY_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning('Identify timeout; closing connection.')
            await websocket.close(code=1008, reason='Identify timeout')
            return None
        except websockets.exceptions.ConnectionClosed:
            logger.warning('Connection closed before identify message received.')
            return None

        # サイズガード（_handle_messageと同様）。
        raw_bytes = raw if isinstance(raw, bytes) else raw.encode('utf-8')
        if len(raw_bytes) > MAX_MESSAGE_BYTES:
            logger.warning('Identify message too large; closing connection.')
            await websocket.close(code=1008, reason='Message too large')
            return None

        try:
            data = json.loads(raw_bytes)
        except json.JSONDecodeError:
            logger.warning('Non-JSON identify message; closing connection.')
            await websocket.close(code=1008, reason='Invalid JSON in identify')
            return None

        # 前方互換性のために {"type": "identify", "browser": "..."} と
        # 素の {"browser": "..."} の両方を受け入れる。
        if not isinstance(data, dict):
            logger.warning('Identify message is not a JSON object; closing connection.')
            await websocket.close(code=1008, reason='Invalid identify format')
            return None

        browser = data.get('browser')
        if not isinstance(browser, str) or not browser:
            logger.warning('Identify message missing browser field; closing connection.')
            await websocket.close(code=1008, reason='Missing browser field in identify')
            return None

        # ブラウザ名を安全な表示可能ASCIIに制限し、ログインジェクションや
        # dictキーの想定外の挙動を防ぐ。
        if not browser.isascii() or not browser.isprintable() or len(browser) > 64:
            logger.warning('Identify browser field contains invalid characters; closing connection.')
            await websocket.close(code=1008, reason='Invalid browser field value')
            return None

        # 許可リスト内のブラウザ名のみ受け入れ、予期しないクライアントが
        # 任意の名前で登録するのを防ぐ。
        if browser not in ALLOWED_BROWSERS:
            logger.warning(
                'Identify browser field not in allowlist: %s; closing connection.',
                _sanitise_for_log(browser),
            )
            await websocket.close(code=1008, reason='Unknown browser')
            return None

        return browser

    async def _handle_message(self, raw: str | bytes) -> None:
        """拡張機能からのコマンドレスポンスメッセージをパースし保存する。

        identifyメッセージはここでは期待されない（メインメッセージループ開始前に
        _receive_identifyで消費される）。

        Args:
            raw: 生のWebSocketメッセージ（バイトまたは文字列）。
        """
        if isinstance(raw, bytes):
            if len(raw) > MAX_MESSAGE_BYTES:
                logger.error('Incoming message exceeds size limit; discarding.')
                self._pending_response = {'result': 'error', 'message': 'Response too large.'}
                self._response_event.set()
                return
            raw = raw.decode('utf-8', errors='replace')
        elif len(raw.encode('utf-8')) > MAX_MESSAGE_BYTES:
            logger.error('Incoming message exceeds size limit; discarding.')
            self._pending_response = {'result': 'error', 'message': 'Response too large.'}
            self._response_event.set()
            return

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning('Received non-JSON response from extension; discarding.')
            self._pending_response = {'result': 'error', 'message': 'Non-JSON response from extension.'}
            self._response_event.set()
            return

        # identifyメッセージはハンドシェイク後に出現すべきではないが、
        # コマンドレスポンスとして扱うのを避けるため黙って無視する。
        if isinstance(data, dict) and data.get('type') == 'identify':
            logger.warning('Unexpected identify message received after handshake; ignoring.')
            return

        self._pending_response = data
        self._response_event.set()

    async def send_command(
        self,
        command: dict[str, Any],
        browser: str | None = None,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        """バリデーション済みコマンドを接続中の拡張機能に送信し、レスポンスを待つ。

        WebSocketラウンドトリップ前に_command_lockを取得し、同時呼び出し元を
        直列化する（サーブモード）。ワンショットモードでは呼び出し元は最大1つのため、
        ロックは競合せずオーバーヘッドもない。

        Args:
            command: バリデーション済みコマンドdict（例: {"cmd": "get_dom"}）。
            browser: 対象ブラウザ名（"firefox"）。Noneの場合:
                     - クライアントが1つだけ接続中ならそれを使用。
                     - 複数接続中ならエラーを返す。
            timeout: 拡張機能の接続とレスポンスの両方を待つ最大秒数。
                     同じ時間枠で両方の待機をカバーする。

        Returns:
            拡張機能からのレスポンスdict。
        """
        async with self._command_lock:
            return await self._send_command_locked(command, browser, timeout)

    async def _send_command_locked(
        self,
        command: dict[str, Any],
        browser: str | None,
        timeout: float,
    ) -> dict[str, Any]:
        """_command_lockを保持した状態でWebSocketラウンドトリップを実行する。

        ロックの不変条件を維持するため、send_commandからのみ呼び出すこと。

        Args:
            command: バリデーション済みコマンドdict。
            browser: 対象ブラウザ名、またはNoneで自動選択。
            timeout: 接続待機とレスポンス待機を合わせた最大秒数。

        Returns:
            拡張機能からのレスポンスdict。
        """
        # 対象クライアントを解決する。必要に応じて待機する。
        client = await self._resolve_client(browser, timeout)
        if isinstance(client, dict):
            # _resolve_clientがエラーdictを返した。
            return client

        self._response_event.clear()
        self._pending_response = None

        try:
            await client.send(json.dumps(command))
        except websockets.exceptions.ConnectionClosed:
            return {'result': 'error', 'message': 'Extension disconnected before command was sent.'}

        try:
            await asyncio.wait_for(self._response_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return {'result': 'error', 'message': f'Timed out waiting for extension response ({timeout}s).'}

        # 切断トリガーのイベントと実際のレスポンスを区別する。
        # handle_connectionはfinallyブロック内でWebSocket閉鎖時に
        # _response_event.set()を呼ぶ。クライアントが残っておらず
        # レスポンスも到着していなければ、待機中に拡張機能が切断されたことを意味する。
        if not self._clients and self._pending_response is None:
            return {'result': 'error', 'message': 'Extension disconnected while waiting for response.'}

        return self._pending_response or {'result': 'error', 'message': 'Empty response from extension.'}

    async def _resolve_client(
        self,
        browser: str | None,
        timeout: float,
    ) -> websockets.server.WebSocketServerProtocol | dict[str, Any]:
        """対象WebSocketクライアントを解決する。必要に応じて接続を待機する。

        Args:
            browser: 希望するブラウザ名、またはNoneで自動選択。
            timeout: クライアント接続を待つ最大秒数。

        Returns:
            解決されたWebSocketServerProtocol、または解決に失敗した場合はエラーdict。
        """
        if browser is not None:
            # 指定されたブラウザの接続を待つ。
            if browser not in self._clients:
                logger.info(
                    'Waiting for %s extension to connect (up to %.0fs)...',
                    _sanitise_for_log(browser),
                    timeout,
                )
                try:
                    await asyncio.wait_for(
                        self._wait_for_client(browser=browser),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    return {
                        'result': 'error',
                        'message': (
                            f'Timed out waiting for {browser} extension. '
                            f'Is FirefoxKontrol loaded in {browser.capitalize()}?'
                        ),
                    }
            client = self._clients.get(browser)
            if client is None:
                # 待機完了とこの参照の間に切断された。
                return {'result': 'error', 'message': f'{browser} extension disconnected unexpectedly.'}
            return client

        # ブラウザ指定なし: クライアントが接続されていなければいずれかの接続を待つ。
        if not self._clients:
            logger.info('Waiting for any extension to connect (up to %.0fs)...', timeout)
            try:
                await asyncio.wait_for(self._wait_for_client(browser=None), timeout=timeout)
            except asyncio.TimeoutError:
                return {
                    'result': 'error',
                    'message': 'Timed out waiting for extension. Is FirefoxKontrol loaded in Firefox?',
                }

        # 自動選択: 接続クライアントが1つだけなら曖昧さがない。
        if len(self._clients) == 1:
            return next(iter(self._clients.values()))

        # 複数クライアント接続中でブラウザ指定なし: エラーを返す。
        connected = ', '.join(sorted(self._clients.keys()))
        return {
            'result': 'error',
            'message': (
                f'Multiple browsers connected ({connected}); '
                f'specify "browser" field to select one.'
            ),
        }

    async def _wait_for_client(self, browser: str | None) -> None:
        """指定されたブラウザ（または任意のブラウザ）が接続するまでブロックする。

        Args:
            browser: 待機対象のブラウザ名、またはNoneで任意のクライアントを待つ。
        """
        while True:
            if browser is not None:
                if browser in self._clients:
                    return
            else:
                if self._clients:
                    return
            await asyncio.sleep(0.1)

    async def run_ping_loop(self, interval: float = 20.0) -> None:
        """接続中の全クライアントに定期的なWebSocket pingを送信し、接続を維持する。

        MV3 Service Workerは約30秒間の非活動後にサスペンドされる。
        ``interval``秒ごとにpingを送信することで、ブラウザが応答すべき
        ネットワークアクティビティを生成し、サスペンドを防止する。

        pingが失敗した場合（接続が既に閉じている）、クライアント参照をクリアし、
        次のコマンド試行時に古いソケットを使わず新しい接続待機が発生するようにする。

        このコルーチンはキャンセルされるまで実行される
        （つまり``run_serve_mode``の存続期間中）。

        Args:
            interval: pingフレーム間の秒数。Service Workerのアイドルタイムアウト
                      （約30秒）より短くする必要がある。十分な安全マージンを
                      確保するため20秒を選択している。
        """
        while True:
            await asyncio.sleep(interval)
            # イテレーション中の変更を避けるためスナップショットを取る。
            clients_snapshot = list(self._clients.items())
            for browser_name, client in clients_snapshot:
                try:
                    pong = await client.ping()
                    await asyncio.wait_for(pong, timeout=5.0)
                except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
                    # スリープとping送信の間にクライアントが切断されたか、
                    # pongが5秒以内に到着しなかった。
                    # handle_connectionのfinallyブロックが_clientsをクリーンアップする。
                    # ここでは何もする必要がない。
                    logger.debug(
                        'Ping failed for browser=%s; awaiting cleanup by handle_connection.',
                        _sanitise_for_log(browser_name),
                    )


# ---------------------------------------------------------------------------
# HTTPコマンドハンドラー（サーブモード）
# ---------------------------------------------------------------------------

async def _handle_http_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    kontrol: FirefoxKontrolServer,
    auth_token: str,
) -> None:
    """サーブモードで単一のHTTPリクエストを処理する。

    HTTP/1.0スタイルのリクエスト全体を読み取り、ボディを抽出し、
    FirefoxKontrolコマンドとしてバリデーションし、WebSocket経由で拡張機能に転送し、
    JSONレスポンスをHTTP/1.1 200レスポンスとして書き戻す。

    設計判断: 追加の依存関係を避けるため、aiohttpやhttp.serverを使わず
    最小限のHTTP/1.1パーサーを実装している。Content-Lengthヘッダー付きの
    POSTリクエストのみサポートする。これはcurlベースの自動化に十分であり、
    攻撃対象面を小さく保つ。

    セキュリティに関する注意:
      - ボディサイズはMAX_MESSAGE_BYTESで制限し、メモリ枯渇を防止する。
      - asyncio.StreamWriterはfinallyブロックで必ず閉じ、fdリークを防ぐ。
      - _validate_commandはWebSocket呼び出し元と同じホワイトリストを再利用する。
      - CSRF対策: X-FirefoxKontrol-Tokenヘッダーをsecrets.compare_digestで検証する。
        タイミング攻撃を防ぐため文字列の等値比較（==）は使用しない。
      - CSRF対策: Content-Type: application/jsonを必須とし、CORS preflightを強制する。
      - トークン値はログおよびエラーレスポンスに含めない（ヘッダー名のみ言及可）。
      - 401応答は欠落・不一致を区別しない（列挙攻撃対策）。

    Args:
        reader: 受信接続用の非同期バイトリーダー。
        writer: レスポンス用の非同期バイトライター。
        kontrol: 共有のFirefoxKontrolServerインスタンス（WSクライアント参照を保持）。
        auth_token: 起動時に生成または環境変数から取得したCSRF対策トークン。
    """
    peer_info = writer.get_extra_info('peername')
    peer = f'{peer_info[0]}:{peer_info[1]}' if peer_info else '?'
    logger.debug('HTTP request from %s', _sanitise_for_log(peer))

    try:
        # ヘッダーを読み取る（二重CRLFで終端）。
        # ヘッダーベースのDoSを緩和するため、ヘッダー読み取りを8 KiBに制限する。
        # 個別の5秒チャンクタイムアウト（1バイトずつ送る低速クライアントにより
        # 無限に延長される可能性がある）ではなく、ヘッダー読み取り全体に
        # 単一の10秒デッドラインを適用する。
        header_buf = b''
        MAX_HEADER_BYTES = 8 * 1024
        header_deadline = asyncio.get_running_loop().time() + 10.0
        while b'\r\n\r\n' not in header_buf:
            remaining_time = header_deadline - asyncio.get_running_loop().time()
            if remaining_time <= 0:
                raise asyncio.TimeoutError
            chunk = await asyncio.wait_for(reader.read(1024), timeout=remaining_time)
            if not chunk:
                break
            header_buf += chunk
            if len(header_buf) > MAX_HEADER_BYTES:
                await _write_http_error(writer, 431, 'Request Header Fields Too Large')
                return

        header_section, _, body_start = header_buf.partition(b'\r\n\r\n')
        header_text = header_section.decode('latin-1', errors='replace')
        # RFC 7230に従いCRLF分割を優先する。非準拠クライアント用にLFにフォールバック。
        lines = header_text.split('\r\n') if '\r\n' in header_text else header_text.split('\n')
        if not lines:
            await _write_http_error(writer, 400, 'Bad Request')
            return

        # HTTPメソッドをバリデーションする（POSTのみ受け付ける）。
        request_line = lines[0]
        parts = request_line.split(' ', 2)
        if len(parts) < 2 or parts[0].upper() != 'POST':
            await _write_http_error(writer, 405, 'Method Not Allowed')
            return

        # リクエストヘッダーを小文字名でdictに収集する（重複は後勝ち）。
        # Content-Length・Content-Type・認証トークンをここで一括取得する。
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, sep, value = line.partition(':')
            if sep:
                headers[name.strip().lower()] = value.strip()

        # CSRF対策: X-FirefoxKontrol-Tokenヘッダーを検証する。
        # secrets.compare_digestでタイミング攻撃を防ぐ。
        # 欠落・不一致ともに同一メッセージで返し、列挙攻撃を防止する。
        # セキュリティ注記: トークン値はログに記録しない。
        request_token = headers.get(HTTP_AUTH_HEADER_NAME.lower(), '')
        if not secrets.compare_digest(request_token, auth_token):
            logger.warning(
                'HTTP request rejected: missing or invalid %s header from %s',
                HTTP_AUTH_HEADER_NAME,
                _sanitise_for_log(peer),
            )
            await _write_http_error(writer, 401, 'Unauthorized')
            return

        # CSRF対策: Content-Type検証。application/json以外を拒否し、
        # CORS preflightを強制することでsimple requestによる攻撃を防止する。
        content_type_raw = headers.get('content-type', '')
        # media-typeのみ比較（; charset=utf-8 等のパラメータを除外）。
        content_type_media = content_type_raw.split(';')[0].strip().lower()
        if content_type_media != REQUIRED_CONTENT_TYPE:
            logger.warning(
                'HTTP request rejected: Content-Type must be %r, got %r from %s',
                REQUIRED_CONTENT_TYPE,
                _sanitise_for_log(content_type_raw),
                _sanitise_for_log(peer),
            )
            await _write_http_error(writer, 415, 'Unsupported Media Type')
            return

        # Content-Lengthを取得・バリデーションする。
        content_length: int | None = None
        raw_cl = headers.get('content-length')
        if raw_cl is not None:
            try:
                content_length = int(raw_cl)
                if content_length < 0:
                    await _write_http_error(writer, 400, 'Bad Request: negative Content-Length')
                    return
            except ValueError:
                await _write_http_error(writer, 400, 'Bad Request: invalid Content-Length')
                return

        if content_length is None:
            await _write_http_error(writer, 411, 'Length Required')
            return

        if content_length > MAX_MESSAGE_BYTES:
            await _write_http_error(writer, 413, 'Request Entity Too Large')
            return

        # 残りのボディバイトを読み取る（header_bufに既にボディの一部が含まれている場合がある）。
        body = body_start
        remaining = content_length - len(body)
        if remaining > 0:
            try:
                extra = await asyncio.wait_for(reader.readexactly(remaining), timeout=10.0)
                body += extra
            except asyncio.IncompleteReadError:
                await _write_http_error(writer, 400, 'Bad Request: incomplete body')
                return

        # コマンドをパースしバリデーションする。
        try:
            raw_cmd: Any = json.loads(body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            await _write_http_error(writer, 400, 'Bad Request: invalid JSON body')
            return

        is_valid, error_msg = _validate_command(raw_cmd)
        if not is_valid:
            response_body = json.dumps({'result': 'error', 'message': error_msg}).encode('utf-8')
            await _write_http_response(writer, 400, response_body)
            return

        # 転送前にオプションのブラウザ指定フィールドを抽出する。
        # _validate_commandで既にstrまたは不在であることが確認済み。
        target_browser: str | None = raw_cmd.get('browser') if isinstance(raw_cmd, dict) else None

        # 拡張機能に転送しレスポンスを返す。
        response = await kontrol.send_command(raw_cmd, browser=target_browser)
        response_body = json.dumps(response).encode('utf-8')
        await _write_http_response(writer, 200, response_body)

    except asyncio.TimeoutError:
        # ヘッダーまたはボディの読み取りがタイムアウトした。クライアントが停滞している可能性がある。
        logger.warning('HTTP request timed out from %s', _sanitise_for_log(peer))
        try:
            await _write_http_error(writer, 408, 'Request Timeout')
        except OSError:
            pass
    except OSError as exc:
        logger.warning('HTTP connection error from %s: %s', _sanitise_for_log(peer), _sanitise_for_log(exc))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            # ソケットが既に閉じている可能性がある。実際のエラーを隠さないよう抑制する。
            pass


async def _write_http_response(writer: asyncio.StreamWriter, status: int, body: bytes) -> None:
    """最小限のHTTP/1.1レスポンスを書き込む。

    Args:
        writer: 接続用の非同期バイトライター。
        status: HTTPステータスコード。
        body: UTF-8エンコードされたJSONボディバイト。
    """
    reason = {200: 'OK', 400: 'Bad Request', 401: 'Unauthorized',
              405: 'Method Not Allowed', 408: 'Request Timeout',
              411: 'Length Required', 413: 'Request Entity Too Large',
              415: 'Unsupported Media Type',
              431: 'Request Header Fields Too Large'}.get(status, 'Unknown')
    response = (
        f'HTTP/1.1 {status} {reason}\r\n'
        f'Content-Type: application/json\r\n'
        f'Content-Length: {len(body)}\r\n'
        f'Connection: close\r\n'
        f'Cache-Control: no-store\r\n'
        f'X-Content-Type-Options: nosniff\r\n'
        f'\r\n'
    ).encode('latin-1') + body
    writer.write(response)
    try:
        await asyncio.wait_for(writer.drain(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.warning('HTTP response write timed out')


async def _write_http_error(writer: asyncio.StreamWriter, status: int, message: str) -> None:
    """JSONエラーレスポンスを書き込む。

    Args:
        writer: 接続用の非同期バイトライター。
        status: HTTPステータスコード。
        message: 人間可読なエラー説明（拡張機能には公開されない）。
    """
    body = json.dumps({'result': 'error', 'message': message}).encode('utf-8')
    await _write_http_response(writer, status, body)


# ---------------------------------------------------------------------------
# サーブモードのエントリーポイント
# ---------------------------------------------------------------------------

async def run_serve_mode(ws_port: int, http_port: int) -> None:
    """WebSocketサーバーとHTTPサーバーを起動し、中断されるまで実行する。

    この関数の動作:
      1. Firefox拡張機能を受け入れるためにWebSocketサーバー（ポートws_port）をバインドする。
      2. curl/スクリプトコマンドを受け入れるためにHTTPサーバー（ポートhttp_port）をバインドする。
      3. CancelledErrorまたはKeyboardInterruptまで両サーバーを無期限に実行する。

    全てのネットワークリスナーはBIND_HOST (127.0.0.1) にのみバインドする。

    Args:
        ws_port: WebSocketサーバー用のTCPポート（デフォルト9767）。
        http_port: HTTPコマンドAPI用のTCPポート（デフォルト9768）。
    """
    kontrol = FirefoxKontrolServer()

    # CSRF対策トークンを生成する。
    # 環境変数 FIREFOX_KONTROL_TOKEN が設定されている場合はそれを使用し、
    # 常駐起動時のトークン固定を可能にする（~/.bashrc等への記載を想定）。
    # 未設定の場合は secrets.token_urlsafe(32) で暗号論的に安全なトークンを生成する。
    # セキュリティ注記: トークン値はstderrにのみ出力する（ローカルプロセスログ、外部に出ない）。
    env_token = os.environ.get('FIREFOX_KONTROL_TOKEN', '')
    auth_token: str = env_token if env_token else secrets.token_urlsafe(32)

    ws_server = await websockets.server.serve(
        kontrol.handle_connection,
        host=BIND_HOST,
        port=ws_port,
        max_size=MAX_MESSAGE_BYTES,
        compression=None,
    )
    logger.info('FirefoxKontrol WebSocket listening on %s:%d', BIND_HOST, ws_port)

    # クロージャがkontrolとauth_tokenをキャプチャし、各接続が同じ状態を共有するようにする。
    async def _http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _handle_http_request(reader, writer, kontrol, auth_token)

    http_server = await asyncio.start_server(
        _http_handler,
        host=BIND_HOST,
        port=http_port,
    )
    logger.info('FirefoxKontrol HTTP API listening on %s:%d', BIND_HOST, http_port)
    logger.info('Auth token: %s', auth_token)
    logger.info(
        'Ready. Send commands with: '
        'TOKEN=%s; curl -s %s:%d '
        '-H "%s: $TOKEN" '
        '-H "Content-Type: application/json" '
        '-d \'{"cmd":"get_dom"}\' '
        '(target: "browser":"firefox")',
        auth_token,
        BIND_HOST,
        http_port,
        HTTP_AUTH_HEADER_NAME,
    )

    ping_task = asyncio.create_task(kontrol.run_ping_loop())

    try:
        async with http_server:
            await http_server.start_serving()
            # KeyboardInterruptによりタスクがキャンセルされるまで無期限にブロックする。
            # Python 3.10+で現在のループがない場合に発生するDeprecationWarningを
            # 避けるため、get_event_loop()ではなくasyncio.get_running_loop()を使用する。
            await asyncio.get_running_loop().create_future()
    except asyncio.CancelledError:
        pass
    finally:
        ping_task.cancel()
        try:
            await ping_task
        except asyncio.CancelledError:
            pass
        ws_server.close()
        await ws_server.wait_closed()
        logger.info('FirefoxKontrol server stopped.')


# ---------------------------------------------------------------------------
# stdinコマンドリーダー（CLIインターフェース）
# ---------------------------------------------------------------------------

async def read_stdin_command() -> Any:
    """stdinからJSON形式のコマンド行を1行読み取る（executorによるノンブロッキング）。

    Returns:
        パース済みJSON値（Any）、またはstdinが閉じている/空の場合はNone。
        構造バリデーションは呼び出し元で_validate_commandにより実行される。
    """
    loop = asyncio.get_running_loop()
    try:
        line: str = await loop.run_in_executor(None, sys.stdin.readline)
    except OSError as exc:
        logger.error('Failed to read from stdin: %s', _sanitise_for_log(exc))
        return None

    line = line.strip()
    if not line:
        return None

    try:
        return json.loads(line)
    except json.JSONDecodeError:
        logger.error('Invalid JSON from stdin: (content hidden for security)')
        return None


# ---------------------------------------------------------------------------
# メインエントリーポイント
# ---------------------------------------------------------------------------

async def run_server(port: int) -> None:
    """WebSocketサーバーを起動し、stdinから1つのコマンドを処理する。

    この関数の動作:
      1. サーバーをlocalhostのみにバインドする。
      2. stdinからJSONコマンドを1つ読み取る。
      3. バリデーションし、接続中のFirefox拡張機能に転送する。
      4. JSONレスポンスをstdoutに書き込む。
      5. 終了する（ワンショットモード）。

    Args:
        port: リッスンするTCPポート。
    """
    kontrol = FirefoxKontrolServer()

    server = await websockets.server.serve(
        kontrol.handle_connection,
        host=BIND_HOST,
        port=port,
        # 過大フレームによるDoSを緩和するため最大メッセージサイズを制限する。
        max_size=MAX_MESSAGE_BYTES,
        # CPU使用量を予測可能に保つため圧縮を無効にする。
        compression=None,
    )

    logger.info('FirefoxKontrol server listening on %s:%d', BIND_HOST, port)

    raw_cmd = await read_stdin_command()
    if raw_cmd is None:
        logger.error('No command received from stdin.')
        server.close()
        await server.wait_closed()
        sys.exit(1)

    is_valid, error_msg = _validate_command(raw_cmd)
    if not is_valid:
        response = {'result': 'error', 'message': error_msg}
        print(json.dumps(response), flush=True)
        server.close()
        await server.wait_closed()
        sys.exit(1)

    # stdinコマンドからオプションのブラウザ指定フィールドを抽出する。
    # _validate_commandで既にstrまたは不在であることが確認済み。
    target_browser: str | None = raw_cmd.get('browser') if isinstance(raw_cmd, dict) else None

    response = await kontrol.send_command(raw_cmd, browser=target_browser)
    print(json.dumps(response), flush=True)

    server.close()
    await server.wait_closed()
    logger.info('Server shut down.')


def _resolve_port(env_var: str, cli_flag: str, default: int, args: list[str]) -> int:
    """環境変数とCLI引数からTCPポートを解決する。

    優先順序: CLI引数 > 環境変数 > デフォルト値。

    Args:
        env_var: チェックする環境変数の名前。
        cli_flag: 探すCLIフラグ名（例: '--port'）。
        default: フォールバック用のデフォルトポート番号。
        args: パース済みsys.argv[1:]のリスト。

    Returns:
        解決されたポート番号（範囲: [1, 65535]）。
    """
    port = default

    env_val = os.environ.get(env_var, '')
    if env_val:
        try:
            parsed = int(env_val)
            if 1 <= parsed <= 65535:
                port = parsed
            else:
                logger.warning('%s value out of range (1-65535); using default %d.', env_var, default)
        except ValueError:
            logger.warning('%s is not a valid integer; using default %d.', env_var, default)

    if cli_flag in args:
        idx = args.index(cli_flag)
        if idx + 1 < len(args):
            try:
                parsed = int(args[idx + 1])
                if 1 <= parsed <= 65535:
                    port = parsed
                else:
                    logger.warning('%s value out of range; using %d.', cli_flag, port)
            except ValueError:
                logger.warning('%s value is not an integer; using %d.', cli_flag, port)

    return port


def main() -> None:
    """CLIエントリーポイント。

    使用方法（ワンショットモード）:
        echo '{"cmd":"get_dom"}' | python3 server.py [--port PORT]
        echo '{"cmd":"get_dom","browser":"firefox"}' | python3 server.py [--port PORT]

    使用方法（サーブモード）:
        python3 server.py --serve [--port PORT] [--http-port PORT]
        TOKEN=$(python3 server.py --serve 2>&1 | grep 'Auth token' | awk '{print $NF}')
        curl -s localhost:9768 -H "X-FirefoxKontrol-Token: $TOKEN" \
          -H "Content-Type: application/json" -d '{"cmd":"get_dom","browser":"firefox"}'

    環境変数:
        FIREFOX_KONTROL_PORT       デフォルトのWebSocketポート（9767）を上書きする。
        FIREFOX_KONTROL_HTTP_PORT  デフォルトのHTTP APIポート（9768）を上書きする。
        FIREFOX_KONTROL_TOKEN      HTTP API認証トークンを固定する（省略時は起動ごとにランダム生成）。
    """
    _configure_logging()

    args = sys.argv[1:]
    serve_mode = '--serve' in args

    ws_port = _resolve_port('FIREFOX_KONTROL_PORT', '--port', DEFAULT_PORT, args)
    http_port = _resolve_port('FIREFOX_KONTROL_HTTP_PORT', '--http-port', DEFAULT_HTTP_PORT, args)

    if serve_mode:
        try:
            asyncio.run(run_serve_mode(ws_port, http_port))
        except KeyboardInterrupt:
            logger.info('Interrupted by user; shutting down.')
            sys.exit(0)
    else:
        try:
            asyncio.run(run_server(ws_port))
        except KeyboardInterrupt:
            logger.info('Interrupted by user.')
            sys.exit(0)


if __name__ == '__main__':
    main()
