<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

/**
 * PDO接続を取得する(シングルトン)。
 * - エラー時は例外を投げる (ERRMODE_EXCEPTION)
 * - プレースホルダのネイティブ実装を強制 (EMULATE_PREPARES = false)
 *   → SQLインジェクション対策の要。文字列連結でSQLを組み立てない。
 */
function bbs_get_pdo(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }

    $dataDir = dirname(BBS_DB_PATH);
    if (!is_dir($dataDir)) {
        mkdir($dataDir, 0770, true);
    }

    $pdo = new PDO('sqlite:' . BBS_DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ]);

    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA journal_mode = WAL');
    $pdo->exec('PRAGMA busy_timeout = 5000');

    bbs_init_schema($pdo);

    return $pdo;
}

/**
 * 指定テーブルに指定カラムが存在しなければ追加する(簡易マイグレーション)。
 * $table, $column, $definition は常にこのファイル内の固定文字列のみを渡す前提
 * (外部入力を渡さない。SQLiteはプレースホルダでテーブル名/カラム名を指定できないため)。
 */
function bbs_ensure_column(PDO $pdo, string $table, string $column, string $definition): void
{
    $stmt = $pdo->query('PRAGMA table_info(' . $table . ')');
    $columns = $stmt->fetchAll(PDO::FETCH_COLUMN, 1);
    if (!in_array($column, $columns, true)) {
        $pdo->exec('ALTER TABLE ' . $table . ' ADD COLUMN ' . $column . ' ' . $definition);
    }
}

function bbs_init_schema(PDO $pdo): void
{
    // スレッド(1つの話題)。最初の投稿(レス1)の内容もここに保持する
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS threads (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            title        TEXT NOT NULL,
            name         TEXT NOT NULL,
            mail         TEXT NOT NULL DEFAULT \'\',
            comment      TEXT NOT NULL,
            delete_hash  TEXT NOT NULL,
            ip_hash      TEXT NOT NULL,
            res_count    INTEGER NOT NULL DEFAULT 1,
            created_at   INTEGER NOT NULL,
            bumped_at    INTEGER NOT NULL
        )
    ');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_threads_bumped_at ON threads (bumped_at DESC)');

    // レス(スレッドへの返信)。レス番号(res_number)はスレッド内で2から始まる連番
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS replies (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id    INTEGER NOT NULL,
            res_number   INTEGER NOT NULL,
            name         TEXT NOT NULL,
            mail         TEXT NOT NULL DEFAULT \'\',
            comment      TEXT NOT NULL,
            delete_hash  TEXT NOT NULL,
            ip_hash      TEXT NOT NULL,
            created_at   INTEGER NOT NULL,
            FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE
        )
    ');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_replies_thread ON replies (thread_id, res_number)');

    // 既存DB向けマイグレーション: レスの論理削除フラグ(ChMate等はdatファイルの
    // 「行の位置」をそのままレス番号として扱うため、削除時に行ごと消してしまうと
    // 以降のレス番号がズレてしまう。そのため物理削除ではなく論理削除にし、
    // 削除済みの行は本文をプレースホルダに置き換えた上でその位置に残す)
    bbs_ensure_column($pdo, 'replies', 'deleted', "INTEGER NOT NULL DEFAULT 0");

    // 連投・投稿頻度制限のための記録(生IPは保存せずハッシュ化して保持)
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS post_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash     TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        )
    ');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_post_log_ip_time ON post_log (ip_hash, created_at)');

    // 管理者ログイン試行記録(ブルートフォース対策)
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS admin_login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_hash     TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            success     INTEGER NOT NULL
        )
    ');
    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_admin_attempts_ip_time ON admin_login_attempts (ip_hash, created_at)');

    // サイト設定(閲覧パスワード・投稿パスワードのON/OFFとハッシュ値など)
    // 管理画面から自由にON/OFF・変更できるよう、ファイルではなくDBに保持する
    $pdo->exec('
        CREATE TABLE IF NOT EXISTS settings (
            key    TEXT PRIMARY KEY,
            value  TEXT NOT NULL
        )
    ');
    $defaults = [
        'view_password_enabled' => '0',
        'view_password_hash'    => '',
        'post_password_enabled' => '0',
        'post_password_hash'    => '',
    ];
    foreach ($defaults as $key => $value) {
        $stmt = $pdo->prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (:k, :v)');
        $stmt->execute([':k' => $key, ':v' => $value]);
    }
}

/** 設定値を取得する。存在しなければ $default を返す。 */
function bbs_get_setting(PDO $pdo, string $key, string $default = ''): string
{
    $stmt = $pdo->prepare('SELECT value FROM settings WHERE key = :k');
    $stmt->execute([':k' => $key]);
    $value = $stmt->fetchColumn();
    return $value === false ? $default : (string)$value;
}

/** 設定値を "1"/"0" として真偽値で取得する。 */
function bbs_get_setting_bool(PDO $pdo, string $key): bool
{
    return bbs_get_setting($pdo, $key, '0') === '1';
}

/** 設定値を保存する(UPSERT)。 */
function bbs_set_setting(PDO $pdo, string $key, string $value): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO settings (key, value) VALUES (:k, :v)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    );
    $stmt->execute([':k' => $key, ':v' => $value]);
}

/**
 * 新規スレッドを作成する。
 * @return int 作成したスレッドのID
 */
function bbs_create_thread(
    PDO $pdo,
    string $title,
    string $name,
    string $mail,
    string $comment,
    string $deleteHash,
    string $ipHash
): int {
    $now = time();
    $stmt = $pdo->prepare(
        'INSERT INTO threads (title, name, mail, comment, delete_hash, ip_hash, res_count, created_at, bumped_at)
         VALUES (:title, :name, :mail, :comment, :dh, :ip, 1, :now, :now)'
    );
    $stmt->execute([
        ':title'   => $title,
        ':name'    => $name,
        ':mail'    => $mail,
        ':comment' => $comment,
        ':dh'      => $deleteHash,
        ':ip'      => $ipHash,
        ':now'     => $now,
    ]);
    return (int)$pdo->lastInsertId();
}

/**
 * スレッドにレスを追加する。
 * レス番号(res_number)の採番とスレッドのres_count更新を同一トランザクション内で
 * 排他的に行うことで、同時書き込みによる採番の重複・欠番を防ぐ。
 *
 * @return array{0: bool, 1: string} [成功したか, 失敗理由(スレッドが存在しない/満員/DBエラー等)]
 */
function bbs_add_reply(
    PDO $pdo,
    int $threadId,
    string $name,
    string $mail,
    string $comment,
    string $deleteHash,
    string $ipHash,
    bool $bump
): array {
    try {
        $pdo->exec('BEGIN IMMEDIATE TRANSACTION');

        $stmt = $pdo->prepare('SELECT res_count FROM threads WHERE id = :id');
        $stmt->execute([':id' => $threadId]);
        $resCount = $stmt->fetchColumn();

        if ($resCount === false) {
            $pdo->exec('ROLLBACK');
            return [false, 'スレッドが見つかりませんでした。'];
        }
        if ((int)$resCount >= BBS_MAX_RES) {
            $pdo->exec('ROLLBACK');
            return [false, 'このスレッドは上限レス数に達しているため書き込めません。'];
        }

        $nextRes = (int)$resCount + 1;
        $now = time();

        $ins = $pdo->prepare(
            'INSERT INTO replies (thread_id, res_number, name, mail, comment, delete_hash, ip_hash, created_at)
             VALUES (:tid, :res, :name, :mail, :comment, :dh, :ip, :now)'
        );
        $ins->execute([
            ':tid'     => $threadId,
            ':res'     => $nextRes,
            ':name'    => $name,
            ':mail'    => $mail,
            ':comment' => $comment,
            ':dh'      => $deleteHash,
            ':ip'      => $ipHash,
            ':now'     => $now,
        ]);

        if ($bump) {
            $upd = $pdo->prepare('UPDATE threads SET res_count = :res, bumped_at = :now WHERE id = :id');
            $upd->execute([':res' => $nextRes, ':now' => $now, ':id' => $threadId]);
        } else {
            $upd = $pdo->prepare('UPDATE threads SET res_count = :res WHERE id = :id');
            $upd->execute([':res' => $nextRes, ':id' => $threadId]);
        }

        $pdo->exec('COMMIT');
        return [true, ''];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->exec('ROLLBACK');
        }
        return [false, '書き込み中にエラーが発生しました。'];
    }
}
