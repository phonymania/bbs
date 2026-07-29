<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib.php';

bbs_send_security_headers();
bbs_start_session();

if (empty($_SESSION['is_admin'])) {
    header('Location: login.php');
    exit;
}

$pdo = bbs_get_pdo();

$threadId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($threadId === null || $threadId === false) {
    header('Location: index.php');
    exit;
}

$stmt = $pdo->prepare('SELECT id, title, name, mail, comment, res_count, created_at FROM threads WHERE id = :id');
$stmt->execute([':id' => $threadId]);
$thread = $stmt->fetch();

if ($thread === false) {
    header('Location: index.php');
    exit;
}

$stmt = $pdo->prepare(
    'SELECT id, res_number, name, mail, comment, created_at FROM replies WHERE thread_id = :tid ORDER BY res_number ASC'
);
$stmt->execute([':tid' => $threadId]);
$replies = $stmt->fetchAll();

$csrfToken = bbs_csrf_token();
$deleted = isset($_GET['deleted']);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>管理画面: <?= h($thread['title']) ?> - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="../style.css">
</head>
<body>
<header class="site-header"><h1>管理画面: <?= h($thread['title']) ?></h1></header>
<main>
  <?php if ($deleted): ?>
    <div class="notice ok">削除しました。</div>
  <?php endif; ?>

  <p>
    <a href="index.php">&laquo; スレッド一覧に戻る</a> ・
    <a href="../thread.php?id=<?= (int)$thread['id'] ?>">掲示板側で見る</a> ・
    <a href="logout.php">ログアウト</a>
  </p>

  <section class="card">
    <div class="post op">
      <div class="post-meta">
        <span class="res-number">1</span>
        <span class="name"><?= h($thread['name']) ?></span>
        <?php if ($thread['mail'] !== ''): ?><span class="mail">[<?= h($thread['mail']) ?>]</span><?php endif; ?>
        ・<?= h(date('Y-m-d H:i:s', (int)$thread['created_at'])) ?>
      </div>
      <div class="post-body"><?= bbs_nl2br_safe(h($thread['comment'])) ?></div>
      <form method="post" action="delete.php">
        <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
        <input type="hidden" name="type" value="thread">
        <input type="hidden" name="id" value="<?= (int)$thread['id'] ?>">
        <button type="submit" class="danger">スレッド全体を削除(全レスも削除されます)</button>
      </form>
    </div>

    <?php foreach ($replies as $r): ?>
      <div class="post">
        <div class="post-meta">
          <span class="res-number"><?= (int)$r['res_number'] ?></span>
          <span class="name"><?= h($r['name']) ?></span>
          <?php if ($r['mail'] !== ''): ?><span class="mail">[<?= h($r['mail']) ?>]</span><?php endif; ?>
          ・<?= h(date('Y-m-d H:i:s', (int)$r['created_at'])) ?>
        </div>
        <div class="post-body"><?= bbs_nl2br_safe(h($r['comment'])) ?></div>
        <form method="post" action="delete.php">
          <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
          <input type="hidden" name="type" value="reply">
          <input type="hidden" name="id" value="<?= (int)$r['id'] ?>">
          <input type="hidden" name="redirect_thread_id" value="<?= (int)$threadId ?>">
          <button type="submit" class="danger">このレスを削除</button>
        </form>
      </div>
    <?php endforeach; ?>
  </section>
</main>
</body>
</html>
