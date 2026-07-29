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
$stmt = $pdo->prepare('DELETE FROM replies WHERE id = :id');
$stmt->execute([':id' => $id]);

if ($redirectThreadId !== null && $redirectThreadId !== false) {
    header('Location: thread.php?id=' . (int)$redirectThreadId . '&deleted=1');
} else {
    header('Location: index.php?deleted=1');
}
exit;
