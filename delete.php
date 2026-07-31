<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

bbs_send_security_headers();
bbs_start_session();
bbs_require_post_method();

$pdo = bbs_get_pdo();
bbs_require_view_unlocked($pdo);

$type = ($_POST['type'] ?? '') === 'thread' ? 'thread' : (($_POST['type'] ?? '') === 'reply' ? 'reply' : null);
$id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
$redirectThreadId = filter_input(INPUT_POST, 'redirect_thread_id', FILTER_VALIDATE_INT);
$password = (string)($_POST['password'] ?? '');

/**
 * 削除処理後の戻り先URLを組み立てる。
 * $queryParam は 'deleted=1' のように、先頭に ? や & を付けない形で渡す(空文字なら付与しない)。
 */
function bbs_delete_back_url(?string $type, $redirectThreadId, string $queryParam): string
{
    if ($type === 'reply' && $redirectThreadId !== null && $redirectThreadId !== false) {
        $base = 'thread.php?id=' . (int)$redirectThreadId;
        return $queryParam === '' ? $base : $base . '&' . $queryParam;
    }
    $base = 'index.php';
    return $queryParam === '' ? $base : $base . '?' . $queryParam;
}

if ($type === null || $id === null || $id === false) {
    header('Location: ' . bbs_delete_back_url($type, $redirectThreadId, ''));
    exit;
}

if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
    http_response_code(400);
    header('Location: ' . bbs_delete_back_url($type, $redirectThreadId, ''));
    exit;
}

// 削除エンドポイントへの総当たりを抑止(種別+IPごとに試行回数を制限)
$ipHash = bbs_ip_hash(bbs_client_ip());
$lockKey = 'delete:' . $type . ':' . $ipHash;
if (bbs_admin_is_locked($pdo, $lockKey)) {
    bbs_csrf_rotate();
    header('Location: ' . bbs_delete_back_url($type, $redirectThreadId, 'error=locked'));
    exit;
}

if ($type === 'thread') {
    $stmt = $pdo->prepare('SELECT delete_hash FROM threads WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();
} else {
    $stmt = $pdo->prepare('SELECT delete_hash, thread_id FROM replies WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $row = $stmt->fetch();
    if ($row !== false) {
        $redirectThreadId = (int)$row['thread_id'];
    }
}

$ok = false;
if ($row !== false && $password !== '') {
    // password_verify自体がタイミングセーフな比較を行う
    $ok = password_verify($password, $row['delete_hash']);
}

bbs_admin_record_attempt($pdo, $lockKey, $ok);
bbs_csrf_rotate();

if ($ok) {
    if ($type === 'thread') {
        $del = $pdo->prepare('DELETE FROM threads WHERE id = :id');
        $del->execute([':id' => $id]);
        header('Location: index.php?deleted=1');
    } else {
        $del = $pdo->prepare('DELETE FROM replies WHERE id = :id');
        $del->execute([':id' => $id]);
        header('Location: ' . bbs_delete_back_url('reply', $redirectThreadId, 'deleted=1'));
    }
    exit;
}

header('Location: ' . bbs_delete_back_url($type, $redirectThreadId, 'error=delete_failed'));
exit;
