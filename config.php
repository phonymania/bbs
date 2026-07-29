<?php
declare(strict_types=1);

/**
 * ============================================================
 *  設定ファイル config.php
 * ------------------------------------------------------------
 *  本番環境で使う前に、必ず以下を変更してください。
 *   1. BBS_SECRET_KEY   … 十分に長いランダム文字列に変更
 *   2. BBS_ADMIN_PASSWORD_HASH … 管理者パスワードのハッシュ値に変更
 *      生成コマンド例:
 *        php -r "echo password_hash('好きなパスワード', PASSWORD_DEFAULT), PHP_EOL;"
 *
 *  可能であれば、このファイルと data/ ディレクトリは
 *  公開ドキュメントルート(例: /var/www/html)の外側に置き、
 *  index.php などから require で読み込む形にしてください。
 * ============================================================
 */

// --- サイト基本設定 ------------------------------------------------
define('BBS_SITE_NAME', '簡易掲示板');
define('BBS_THREADS_PER_PAGE', 20);  // 板トップに表示するスレッド数
define('BBS_RES_PER_PAGE', 50);      // スレッド内、1ページに表示するレス数
define('BBS_NAME_MAX', 30);          // 名前欄の最大文字数
define('BBS_MAIL_MAX', 30);          // メール欄の最大文字数
define('BBS_TITLE_MAX', 60);         // スレッドタイトルの最大文字数
define('BBS_COMMENT_MAX', 1000);     // 本文の最大文字数
define('BBS_PASSWORD_MAX', 30);      // 削除用パスワードの最大文字数
define('BBS_MAX_RES', 1000);         // 1スレッドあたりの最大レス数(これを超えると書き込み不可)

// --- 投稿頻度制限(連投・Bot対策) -------------------------------------
define('BBS_POST_INTERVAL', 10);     // 同一IPからの連続投稿を禁止する秒数
define('BBS_POST_PER_HOUR', 20);     // 同一IPからの1時間あたり投稿数上限
define('BBS_MIN_SUBMIT_TIME', 3);    // フォーム表示〜送信までの最短許容秒数
define('BBS_MAX_SUBMIT_TIME', 3600); // フォームトークンの有効期限(秒)

// --- 管理者ログイン試行制限(ブルートフォース対策) -----------------------
define('BBS_ADMIN_MAX_ATTEMPTS', 5);   // この回数失敗したらロック
define('BBS_ADMIN_LOCK_SECONDS', 600); // ロックする秒数

// --- データベース ----------------------------------------------------
define('BBS_DB_PATH', __DIR__ . '/data/bbs.sqlite3');

// --- 秘密鍵 (HMAC署名・IPハッシュ化などに使用) --------------------------
// !!! 本番環境では必ず変更してください !!!
define('BBS_SECRET_KEY', '78b91fcbd9c0128e9eb48b134538e53089b46d45cc115a7a67720b3d0c8dd377');

// --- 管理者パスワードハッシュ ------------------------------------------
// デフォルトは "changeme123" のハッシュです。必ず変更してください。
define('BBS_ADMIN_PASSWORD_HASH', '$2y$10$WaOMe5V2KyuG3NDqXAfOseG2h87I5LmgpC9d.U1zt2NNGNQRE.IsS');

// --- Cookie / Session 名 ----------------------------------------------
define('BBS_SESSION_NAME', 'BBSSESSID');
