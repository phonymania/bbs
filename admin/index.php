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

$page = bbs_get_page_param();
$perPage = BBS_THREADS_PER_PAGE;
$total = (int)$pdo->query('SELECT COUNT(*) FROM threads')->fetchColumn();
$totalPages = max(1, (int)ceil($total / $perPage));
if ($page > $totalPages) {
    $page = $totalPages;
}
$offset = ($page - 1) * $perPage;

$stmt = $pdo->prepare(
    'SELECT id, title, name, comment, res_count, created_at, bumped_at
     FROM threads ORDER BY bumped_at DESC, id DESC LIMIT :limit OFFSET :offset'
);
$stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$threads = $stmt->fetchAll();

$csrfToken = bbs_csrf_token();

$deleted = isset($_GET['deleted']);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>管理画面 - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="../style.css">
</head>
<body>
<header class="site-header"><h1>管理画面(スレッド一覧)</h1></header>
<main>
  <?php if ($deleted): ?>
    <div class="notice ok">削除しました。</div>
  <?php endif; ?>

  <p>
    <a href="../index.php">&laquo; 掲示板に戻る</a> ・
    <a href="logout.php">ログアウト</a>
  </p>

  <section class="card">
    <h2>スレッド一覧(全<?= (int)$total ?>件・管理者権限で削除可)</h2>
    <?php if (empty($threads)): ?>
      <p>まだスレッドがありません。</p>
    <?php endif; ?>

    <?php foreach ($threads as $t): ?>
      <div class="post">
        <div class="post-meta">
          <span class="name"><?= h($t['title']) ?></span>
          ・No.<?= (int)$t['id'] ?>
          ・レス数 <?= (int)$t['res_count'] ?>
          ・<?= h(date('Y-m-d H:i:s', (int)$t['created_at'])) ?>
        </div>
        <div class="post-body"><?= h(bbs_excerpt($t['comment'], 80)) ?></div>
        <p>
          <a href="thread.php?id=<?= (int)$t['id'] ?>">レス一覧を見る/個別に削除</a>
        </p>
        <form method="post" action="delete.php">
          <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
          <input type="hidden" name="type" value="thread">
          <input type="hidden" name="id" value="<?= (int)$t['id'] ?>">
          <button type="submit" class="danger">このスレッド全体を削除</button>
        </form>
      </div>
    <?php endforeach; ?>

    <?php if ($totalPages > 1): ?>
      <div class="pagination">
        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
          <?php if ($p === $page): ?>
            <span class="current"><?= $p ?></span>
          <?php else: ?>
            <a href="index.php?page=<?= $p ?>"><?= $p ?></a>
          <?php endif; ?>
        <?php endfor; ?>
      </div>
    <?php endif; ?>
  </section>
</main>
</body>
</html>
