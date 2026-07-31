<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/db.php';

mb_internal_encoding('UTF-8');

/* ============================================================
 * HTML出力エスケープ (XSS対策)
 * どこかに `echo $userInput;` と直書きしないことを徹底し、
 * 必ずこの関数を通してから出力する。
 * ============================================================ */
function h(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* ============================================================
 * HTTPS判定 (リバースプロキシ配下も一応考慮)
 * ============================================================ */
function bbs_is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if (($_SERVER['SERVER_PORT'] ?? null) === '443') {
        return true;
    }
    return false;
}

/* ============================================================
 * セキュリティ関連HTTPヘッダーの送信
 * - JavaScriptを一切使わないサイトなので script-src は 'none' に固定できる
 * - クリックジャッキング対策 (X-Frame-Options / frame-ancestors)
 * - MIMEスニッフィング対策
 * - リファラ漏えい対策
 * 呼び出しは各ページの一番最初、何も出力する前に行うこと。
 * ============================================================ */
function bbs_send_security_headers(): void
{
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'none'; " .
        "img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('X-XSS-Protection: 0'); // 現代ブラウザでは非推奨機能。CSPで代替。
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    if (bbs_is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/* ============================================================
 * セッション開始 (セッション固定攻撃・Cookie窃取対策込み)
 * ============================================================ */
function bbs_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');
    ini_set('session.cookie_samesite', 'Strict');
    ini_set('session.cookie_secure', bbs_is_https() ? '1' : '0');
    ini_set('session.sid_length', '48');

    session_name(BBS_SESSION_NAME);
    session_start();

    // 一定時間ごとにセッションIDを再発行し、セッション固定/長期間の使い回しを防ぐ
    if (!isset($_SESSION['_started_at'])) {
        $_SESSION['_started_at'] = time();
    } elseif (time() - $_SESSION['_started_at'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['_started_at'] = time();
    }
}

/* ============================================================
 * CSRFトークン (フォーム送信の正当性検証)
 * ============================================================ */
function bbs_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function bbs_csrf_verify(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || $token === null || $token === '') {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/** 状態変更が成功した後にトークンを再発行し、再送・使い回しの窓を狭める */
function bbs_csrf_rotate(): void
{
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

/* ============================================================
 * フォーム用の時刻付きトークン (簡易Bot対策)
 * - HMACで署名し、改ざん・偽造を防ぐ
 * - 表示から一定秒数(BBS_MIN_SUBMIT_TIME)未満での送信は機械的投稿とみなす
 * - 有効期限(BBS_MAX_SUBMIT_TIME)を過ぎたトークンは無効(リプレイ対策)
 * ============================================================ */
function bbs_form_timing_token(): string
{
    $ts = (string)time();
    $sig = hash_hmac('sha256', $ts, BBS_SECRET_KEY);
    return $ts . '.' . $sig;
}

function bbs_verify_form_timing_token(?string $token): bool
{
    if ($token === null || strpos($token, '.') === false) {
        return false;
    }
    [$ts, $sig] = explode('.', $token, 2);
    if (!ctype_digit($ts)) {
        return false;
    }
    $expected = hash_hmac('sha256', $ts, BBS_SECRET_KEY);
    if (!hash_equals($expected, $sig)) {
        return false;
    }
    $elapsed = time() - (int)$ts;
    if ($elapsed < BBS_MIN_SUBMIT_TIME) {
        return false; // 速すぎる = Botの疑い
    }
    if ($elapsed > BBS_MAX_SUBMIT_TIME) {
        return false; // 古すぎる = 期限切れ/リプレイの疑い
    }
    return true;
}

/* ============================================================
 * クライアントIPの取得とハッシュ化
 * - X-Forwarded-For 等は偽装可能なため信頼しない(REMOTE_ADDRのみ使用)。
 *   リバースプロキシ配下で正しいIPを得たい場合は、信頼できるプロキシの
 *   IPからのみ X-Forwarded-For を採用するようインフラ側で設定すること。
 * - 生IPはDBに保存せず、秘密鍵付きHMACでハッシュ化してから保存する(プライバシー配慮)。
 * ============================================================ */
function bbs_client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function bbs_ip_hash(string $ip): string
{
    return hash_hmac('sha256', $ip, BBS_SECRET_KEY);
}

/* ============================================================
 * 入力検証・サニタイズ
 * - 不正なUTF-8を拒否(マルチバイト関連の脆弱性対策)
 * - 改行/タブ以外の制御文字を除去
 * - 文字数上限を超えるものは拒否
 * ============================================================ */
function bbs_clean_text(string $raw, int $maxLen): ?string
{
    if (!mb_check_encoding($raw, 'UTF-8')) {
        return null;
    }
    // 改行(LF, CR)・タブ以外の制御文字を除去
    $clean = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $raw);
    if ($clean === null) {
        return null;
    }
    $clean = trim($clean);
    $len = mb_strlen($clean, 'UTF-8');
    if ($len > $maxLen) {
        return null;
    }
    return $clean;
}

/** 改行を <br> に変換して表示するためのヘルパー(必ずエスケープ後に使う) */
function bbs_nl2br_safe(string $escapedHtml): string
{
    return nl2br($escapedHtml, false);
}

/** スレッド一覧などで使う本文抜粋(エスケープ前の生テキストに対して使用し、呼び出し側でh()すること) */
function bbs_excerpt(string $text, int $maxLen): string
{
    $oneLine = str_replace(["\r\n", "\r", "\n"], ' ', $text);
    if (mb_strlen($oneLine, 'UTF-8') > $maxLen) {
        return mb_substr($oneLine, 0, $maxLen, 'UTF-8') . '…';
    }
    return $oneLine;
}

/** メール欄に "sage" が指定されているか判定する(大文字小文字を区別しない) */
function bbs_is_sage(string $mail): bool
{
    return strtolower(trim($mail)) === 'sage';
}

/* ============================================================
 * トリップ機能 ( 名前#トリップ鍵 → 名前 ◆xxxxxxxxxx )
 * ※ 元祖2chのDES-crypt方式ではなく、秘密鍵付きHMAC-SHA256による
 *   独自方式(同じ鍵なら誰が計算しても同じトリップになる、という
 *   本人確認の役割は同様に果たしつつ、より安全なハッシュ関数を使用)。
 * ============================================================ */
function bbs_generate_trip(string $tripKey): string
{
    $hash = hash_hmac('sha256', $tripKey, BBS_SECRET_KEY);
    return '◆' . substr($hash, 0, 10);
}

/**
 * 名前欄の入力を処理する。"名前#トリップ鍵" の形式であればトリップを付与する。
 * 不正な入力(文字数超過・不正なUTF-8)の場合は null を返す。
 */
function bbs_process_name(string $rawName): ?string
{
    $hashPos = mb_strpos($rawName, '#', 0, 'UTF-8');

    if ($hashPos === false) {
        $clean = bbs_clean_text($rawName, BBS_NAME_MAX);
        if ($clean === null) {
            return null;
        }
        return $clean === '' ? '名無しさん' : $clean;
    }

    $displayPart = mb_substr($rawName, 0, $hashPos, 'UTF-8');
    $tripKeyPart = mb_substr($rawName, $hashPos + 1, null, 'UTF-8');

    $displayClean = bbs_clean_text($displayPart, BBS_NAME_MAX);
    $tripKeyClean = bbs_clean_text($tripKeyPart, BBS_NAME_MAX);
    if ($displayClean === null || $tripKeyClean === null) {
        return null;
    }

    $displayName = $displayClean === '' ? '名無しさん' : $displayClean;
    if ($tripKeyClean === '') {
        return $displayName;
    }

    return $displayName . ' ' . bbs_generate_trip($tripKeyClean);
}

/* ============================================================
 * >>N 形式のレス番号参照を、ページ内アンカーリンクに変換する。
 * 必ず htmlspecialchars() 済みの文字列に対して適用すること
 * (エスケープ後は ">" が "&gt;" になっているため、その形で照合する)。
 * 生成するHTMLは数値のみを埋め込んで組み立てるため安全。
 * ============================================================ */
function bbs_linkify_anchors(string $escapedComment): string
{
    return preg_replace_callback(
        '/&gt;&gt;(\d{1,4})/',
        static function (array $m): string {
            $n = (int)$m[1];
            return '<a href="#res-' . $n . '" class="anchor-link">&gt;&gt;' . $n . '</a>';
        },
        $escapedComment
    );
}

/**
 * スレッド/レスの削除用フォーム(HTML)を生成する。
 * $type は 'thread' または 'reply'。出力前提のため呼び出し側でのエスケープは不要。
 */
function bbs_render_delete_form(string $type, int $id, string $csrfToken, ?int $redirectThreadId = null): string
{
    $label = $type === 'thread' ? 'このスレッド自体を削除する(全レスも削除されます)' : 'このレスを削除する';
    $idFieldId = 'del_password_' . $type . '_' . $id;
    $redirectField = '';
    if ($redirectThreadId !== null) {
        $redirectField = '<input type="hidden" name="redirect_thread_id" value="' . $redirectThreadId . '">';
    }
    return '
        <details class="delete-box">
          <summary>' . h($label) . '</summary>
          <form method="post" action="delete.php">
            <input type="hidden" name="csrf_token" value="' . h($csrfToken) . '">
            <input type="hidden" name="type" value="' . h($type) . '">
            <input type="hidden" name="id" value="' . $id . '">
            ' . $redirectField . '
            <div class="field">
              <label for="' . h($idFieldId) . '">削除用パスワード</label>
              <input type="password" id="' . h($idFieldId) . '" name="password" maxlength="' . BBS_PASSWORD_MAX . '" autocomplete="off">
            </div>
            <button type="submit" class="danger">削除する</button>
          </form>
        </details>';
}

/* ============================================================
 * 閲覧パスワード / 投稿パスワード (管理人がON/OFFを自由に切替可能)
 * ------------------------------------------------------------
 * - 有効になっている場合、パスワードのハッシュ値をセッションに
 *   保持している人だけが通過できる。
 * - 「セッションにハッシュ値そのものを保持し、現在の設定ハッシュと
 *   一致するかを毎回確認する」方式のため、管理人がパスワードを
 *   変更した瞬間に、既存のセッションは自動的に再ロックされる。
 * - 管理者(is_admin)は常に両方とも素通りできる。
 * ============================================================ */
function bbs_is_view_unlocked(PDO $pdo): bool
{
    if (!empty($_SESSION['is_admin'])) {
        return true;
    }
    if (!bbs_get_setting_bool($pdo, 'view_password_enabled')) {
        return true;
    }
    $currentHash = bbs_get_setting($pdo, 'view_password_hash', '');
    if ($currentHash === '') {
        // 有効化されているのにパスワード未設定 = 安全側に倒して誰も通さない
        return false;
    }
    return isset($_SESSION['view_unlocked_hash']) && hash_equals($currentHash, $_SESSION['view_unlocked_hash']);
}

/** 閲覧ロックがかかっていれば gate.php へリダイレクトする。呼び出し側の処理は続行しない。 */
function bbs_require_view_unlocked(PDO $pdo): void
{
    if (bbs_is_view_unlocked($pdo)) {
        return;
    }
    $target = $_SERVER['REQUEST_URI'] ?? 'index.php';
    header('Location: gate.php?redirect=' . urlencode($target));
    exit;
}

function bbs_is_post_unlocked(PDO $pdo): bool
{
    if (!empty($_SESSION['is_admin'])) {
        return true;
    }
    if (!bbs_get_setting_bool($pdo, 'post_password_enabled')) {
        return true;
    }
    $currentHash = bbs_get_setting($pdo, 'post_password_hash', '');
    if ($currentHash === '') {
        return false;
    }
    return isset($_SESSION['post_unlocked_hash']) && hash_equals($currentHash, $_SESSION['post_unlocked_hash']);
}

/**
 * 投稿用パスワードを検証し、正しければセッションに記録して true を返す。
 * (有効化されていない場合は常に true)
 */
function bbs_try_unlock_post(PDO $pdo, string $input): bool
{
    if (bbs_is_post_unlocked($pdo)) {
        return true;
    }
    $currentHash = bbs_get_setting($pdo, 'post_password_hash', '');
    if ($currentHash === '' || $input === '') {
        return false;
    }
    if (password_verify($input, $currentHash)) {
        $_SESSION['post_unlocked_hash'] = $currentHash;
        return true;
    }
    return false;
}

/**
 * gate.php のリダイレクト先パラメータを検証する(オープンリダイレクト対策)。
 * "index.php" または "thread.php?id=数字" の形しか許可しない。
 */
function bbs_sanitize_redirect_target(?string $target): string
{
    if ($target === null) {
        return 'index.php';
    }
    $target = ltrim($target, '/');
    if (preg_match('/^index\.php$/', $target)) {
        return 'index.php';
    }
    if (preg_match('/^thread\.php\?id=([0-9]+)$/', $target, $m)) {
        return 'thread.php?id=' . $m[1];
    }
    return 'index.php';
}

/* ============================================================
 * 投稿頻度制限 (連投・スパム対策)
 * ============================================================ */
function bbs_check_rate_limit(PDO $pdo, string $ipHash): array
{
    $now = time();

    $stmt = $pdo->prepare('SELECT created_at FROM post_log WHERE ip_hash = :ip ORDER BY created_at DESC LIMIT 1');
    $stmt->execute([':ip' => $ipHash]);
    $last = $stmt->fetchColumn();
    if ($last !== false && ($now - (int)$last) < BBS_POST_INTERVAL) {
        $wait = BBS_POST_INTERVAL - ($now - (int)$last);
        return [false, "投稿間隔が短すぎます。あと{$wait}秒待ってから再度お試しください。"];
    }

    $stmt = $pdo->prepare('SELECT COUNT(*) FROM post_log WHERE ip_hash = :ip AND created_at > :since');
    $stmt->execute([':ip' => $ipHash, ':since' => $now - 3600]);
    $count = (int)$stmt->fetchColumn();
    if ($count >= BBS_POST_PER_HOUR) {
        return [false, '投稿数の上限に達しました。しばらく時間をおいてから再度お試しください。'];
    }

    return [true, ''];
}

function bbs_record_post(PDO $pdo, string $ipHash): void
{
    $stmt = $pdo->prepare('INSERT INTO post_log (ip_hash, created_at) VALUES (:ip, :now)');
    $stmt->execute([':ip' => $ipHash, ':now' => time()]);
}

/* ============================================================
 * 管理者ログイン試行制限 (ブルートフォース対策)
 * ============================================================ */
function bbs_admin_is_locked(PDO $pdo, string $ipHash): bool
{
    $since = time() - BBS_ADMIN_LOCK_SECONDS;
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM admin_login_attempts
         WHERE ip_hash = :ip AND success = 0 AND created_at > :since'
    );
    $stmt->execute([':ip' => $ipHash, ':since' => $since]);
    return (int)$stmt->fetchColumn() >= BBS_ADMIN_MAX_ATTEMPTS;
}

function bbs_admin_record_attempt(PDO $pdo, string $ipHash, bool $success): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO admin_login_attempts (ip_hash, created_at, success) VALUES (:ip, :now, :ok)'
    );
    $stmt->execute([':ip' => $ipHash, ':now' => time(), ':ok' => $success ? 1 : 0]);
}

/* ============================================================
 * ページネーション用の整数パラメータ取得(ホワイトリスト式)
 * ============================================================ */
function bbs_get_page_param(): int
{
    $page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1, 'default' => 1],
    ]);
    return $page ?: 1;
}

/* ============================================================
 * リクエストメソッド検証(状態変更エンドポイントはPOSTのみ許可)
 * ============================================================ */
function bbs_require_post_method(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        http_response_code(405);
        header('Allow: POST');
        echo '許可されていないリクエストメソッドです。';
        exit;
    }
}
