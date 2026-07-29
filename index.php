<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

bbs_send_security_headers();
bbs_start_session();
$pdo = bbs_get_pdo();

$errors = [];
$successMessage = null;

/* ------------------------------------------------------------
 * 新規スレッド作成の受付 (POST)
 * Post/Redirect/Get パターンで二重投稿を防止する
 * ------------------------------------------------------------ */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'new_thread') {

    if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = '不正なリクエストです。ページを再読み込みしてもう一度お試しください。';
    }

    if (empty($errors) && !bbs_verify_form_timing_token($_POST['form_token'] ?? null)) {
        $errors[] = '送信のタイミングが正しくありません。もう一度お試しください。';
    }

    // ハニーポット: 隠しフィールドに何か入力されていれば機械的な投稿とみなす
    $isBot = (($_POST['website'] ?? '') !== '');

    $title = null;
    $name = null;
    $mail = null;
    $comment = null;
    $password = null;

    if (empty($errors)) {
        $title = bbs_clean_text((string)($_POST['title'] ?? ''), BBS_TITLE_MAX);
        if ($title === null || $title === '') {
            $errors[] = 'スレッドタイトルを入力してください(' . BBS_TITLE_MAX . '文字以内)。';
        }

        $name = bbs_process_name((string)($_POST['name'] ?? ''));
        if ($name === null) {
            $errors[] = '名前が長すぎるか、使用できない文字が含まれています。';
        }

        $mail = bbs_clean_text((string)($_POST['mail'] ?? ''), BBS_MAIL_MAX);
        if ($mail === null) {
            $errors[] = 'メール欄が長すぎます。';
            $mail = '';
        }

        $comment = bbs_clean_text((string)($_POST['comment'] ?? ''), BBS_COMMENT_MAX);
        if ($comment === null || $comment === '') {
            $errors[] = '本文を入力してください(' . BBS_COMMENT_MAX . '文字以内)。';
        }

        $password = bbs_clean_text((string)($_POST['password'] ?? ''), BBS_PASSWORD_MAX);
        if ($password === null) {
            $errors[] = '削除用パスワードが長すぎます。';
        }
    }

    $ipHash = bbs_ip_hash(bbs_client_ip());

    if (empty($errors) && !$isBot) {
        [$allowed, $reason] = bbs_check_rate_limit($pdo, $ipHash);
        if (!$allowed) {
            $errors[] = $reason;
        }
    }

    if ($isBot) {
        bbs_csrf_rotate();
        header('Location: index.php?posted=1');
        exit;
    }

    if (empty($errors)) {
        $passwordForHash = ($password !== null && $password !== '') ? $password : bin2hex(random_bytes(16));
        $deleteHash = password_hash($passwordForHash, PASSWORD_DEFAULT);

        $threadId = bbs_create_thread($pdo, $title, $name, $mail, $comment, $deleteHash, $ipHash);
        bbs_record_post($pdo, $ipHash);
        bbs_csrf_rotate();

        header('Location: thread.php?id=' . $threadId);
        exit;
    }
}

if (isset($_GET['posted'])) {
    $successMessage = 'スレッドを作成しました。';
} elseif (isset($_GET['deleted'])) {
    $successMessage = 'スレッドを削除しました。';
} elseif (($_GET['error'] ?? '') === 'delete_failed') {
    $errors[] = '削除用パスワードが正しくないか、スレッドが見つかりませんでした。';
} elseif (($_GET['error'] ?? '') === 'locked') {
    $errors[] = '削除の試行回数が多すぎます。しばらく時間をおいてから再度お試しください。';
}

/* ------------------------------------------------------------
 * スレッド一覧の取得(勢いのある=bumped_atが新しい順、ページネーション)
 * ------------------------------------------------------------ */
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
$formToken = bbs_form_timing_token();
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="site-header">
  <h1><?= h(BBS_SITE_NAME) ?></h1>
</header>

<main>

  <?php if ($successMessage !== null): ?>
    <div class="notice ok"><?= h($successMessage) ?></div>
  <?php endif; ?>

  <?php if (!empty($errors)): ?>
    <div class="notice error">
      <?php foreach ($errors as $e): ?>
        <div><?= h($e) ?></div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>

  <section class="card">
    <h2>新規スレッド作成</h2>
    <form method="post" action="index.php" autocomplete="off">
      <input type="hidden" name="action" value="new_thread">
      <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
      <input type="hidden" name="form_token" value="<?= h($formToken) ?>">

      <!-- ハニーポット: 人間には見えない欄。ボットがここに入力すると投稿は無視される -->
      <div class="field hp-field" aria-hidden="true">
        <label for="website">Webサイト(空欄のままにしてください)</label>
        <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
      </div>

      <div class="field">
        <label for="title">スレッドタイトル(必須・<?= BBS_TITLE_MAX ?>文字以内)</label>
        <input type="text" id="title" name="title" maxlength="<?= BBS_TITLE_MAX ?>" required>
      </div>

      <div class="row2">
        <div class="field">
          <label for="name">お名前(任意・<?= BBS_NAME_MAX ?>文字以内・「名前#トリップ鍵」でトリップ表示可)</label>
          <input type="text" id="name" name="name" maxlength="<?= BBS_NAME_MAX ?>" placeholder="名無しさん">
        </div>
        <div class="field">
          <label for="mail">メール欄(任意・sageで age しない)</label>
          <input type="text" id="mail" name="mail" maxlength="<?= BBS_MAIL_MAX ?>" placeholder="sage">
        </div>
      </div>

      <div class="field">
        <label for="comment">本文(必須・<?= BBS_COMMENT_MAX ?>文字以内)</label>
        <textarea id="comment" name="comment" maxlength="<?= BBS_COMMENT_MAX ?>" required></textarea>
      </div>

      <div class="field">
        <label for="password">削除用パスワード(任意・<?= BBS_PASSWORD_MAX ?>文字以内)</label>
        <input type="password" id="password" name="password" maxlength="<?= BBS_PASSWORD_MAX ?>" autocomplete="new-password">
      </div>

      <button type="submit">スレッドを立てる</button>
    </form>
  </section>

  <section class="card">
    <h2>スレッド一覧(全<?= (int)$total ?>件)</h2>

    <?php if (empty($threads)): ?>
      <p>まだスレッドがありません。</p>
    <?php endif; ?>

    <ol class="thread-list">
      <?php foreach ($threads as $t): ?>
        <li class="thread-list-item">
          <a class="thread-title" href="thread.php?id=<?= (int)$t['id'] ?>"><?= h($t['title']) ?></a>
          <span class="thread-meta">(<?= (int)$t['res_count'] ?>)</span>
          <div class="thread-excerpt"><?= h(bbs_excerpt($t['comment'], 60)) ?></div>
        </li>
      <?php endforeach; ?>
    </ol>

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

<footer>
  <?= h(BBS_SITE_NAME) ?> &mdash; <a href="admin/login.php">管理者ログイン</a>
</footer>
</body>
</html>
