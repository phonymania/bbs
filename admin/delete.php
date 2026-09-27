<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib.php';

bbs_send_security_headers();
bbs_start_session();
bbs_require_post_method();

if (empty($_SESSION['is_admin'])) {
    header('Location: login.php');
    exit;
}

if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
    http_response_code(400);
    header('Location: index.php');
    exit;
}

$pdo = bbs_get_pdo();

$type = ($_POST['type'] ?? '') === 'thread' ? 'thread' : (($_POST['type'] ?? '') === 'reply' ? 'reply' : null);
$id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT);
$redirectThreadId = filter_input(INPUT_POST, 'redirect_thread_id', FILTER_VALIDATE_INT);

bbs_csrf_rotate();

if ($type === null || $id === null || $id === false) {
    header('Location: index.php');
    exit;
}

if ($type === 'thread') {
    $stmt = $pdo->prepare('DELETE FROM threads WHERE id = :id');
    $stmt->execute([':id' => $id]);
    header('Location: index.php?deleted=1');
    exit;
}

// reply
$purge = ($_POST['purge'] ?? '') === '1';

if ($purge) {
    // 完全に削除(物理削除)。違法コンテンツ等でどうしても内容を残したくない場合用。
    // ChMate等の専用ブラウザから見た場合、以降のレス番号(行位置)がズレる点に注意。
    $stmt = $pdo->prepare('DELETE FROM replies WHERE id = :id');
    $stmt->execute([':id' => $id]);
} else {
    // 通常は論理削除(行の位置=レス番号を維持したまま内容だけ置き換える)
    $stmt = $pdo->prepare(
        "UPDATE replies SET deleted = 1, name = :name, mail = '', comment = :comment WHERE id = :id"
    );
    $stmt->execute([
        ':id'      => $id,
        ':name'    => '(削除済み)',
        ':comment' => '管理者により削除されました。',
    ]);
}

if ($redirectThreadId !== null && $redirectThreadId !== false) {
    header('Location: thread.php?id=' . (int)$redirectThreadId . '&deleted=1');
} else {
    header('Location: index.php?deleted=1');
}
exit;
