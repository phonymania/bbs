<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

bbs_send_security_headers();
bbs_start_session();
$pdo = bbs_get_pdo();
bbs_require_view_unlocked($pdo);

$threadId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($threadId === null || $threadId === false) {
    http_response_code(400);
    header('Location: index.php');
    exit;
}

$errors = [];
$successMessage = null;

/* ------------------------------------------------------------
 * レス投稿の受付 (POST)
 * ------------------------------------------------------------ */
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && ($_POST['action'] ?? '') === 'new_reply') {

    $postThreadId = filter_input(INPUT_POST, 'thread_id', FILTER_VALIDATE_INT);
    if ($postThreadId !== $threadId) {
        $errors[] = '不正なリクエストです。';
    }

    if (empty($errors) && !bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = '不正なリクエストです。ページを再読み込みしてもう一度お試しください。';
    }

    if (empty($errors) && !bbs_verify_form_timing_token($_POST['form_token'] ?? null)) {
        $errors[] = '送信のタイミングが正しくありません。もう一度お試しください。';
    }

    $isBot = (($_POST['website'] ?? '') !== '');

    $name = null;
    $mail = null;
    $comment = null;
    $password = null;

    if (empty($errors)) {
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

        if (!bbs_try_unlock_post($pdo, (string)($_POST['site_post_password'] ?? ''))) {
            $errors[] = '投稿用パスワードが正しくありません。';
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
        header('Location: thread.php?id=' . $threadId . '&posted=1');
        exit;
    }

    if (empty($errors)) {
        $passwordForHash = ($password !== null && $password !== '') ? $password : bin2hex(random_bytes(16));
        $deleteHash = password_hash($passwordForHash, PASSWORD_DEFAULT);
        $bump = !bbs_is_sage($mail);

        [$ok, $reason] = bbs_add_reply($pdo, $threadId, $name, $mail, $comment, $deleteHash, $ipHash, $bump);
        if ($ok) {
            bbs_record_post($pdo, $ipHash);
            bbs_csrf_rotate();

            $newResCount = (int)$pdo->query('SELECT res_count FROM threads WHERE id = ' . (int)$threadId)->fetchColumn();
            $lastPage = max(1, (int)ceil($newResCount / BBS_RES_PER_PAGE));
            header('Location: thread.php?id=' . $threadId . '&page=' . $lastPage . '&posted=1');
            exit;
        }
        $errors[] = $reason;
    }
}

/* ------------------------------------------------------------
 * スレッド本体の取得
 * ------------------------------------------------------------ */
$stmt = $pdo->prepare('SELECT id, title, name, mail, comment, res_count, created_at FROM threads WHERE id = :id');
$stmt->execute([':id' => $threadId]);
$thread = $stmt->fetch();

if ($thread === false) {
    bbs_send_security_headers();
    ?>
    <!DOCTYPE html>
    <html lang="ja">
    <head><meta charset="UTF-8"><title>スレッドが見つかりません - <?= h(BBS_SITE_NAME) ?></title>
    <link rel="stylesheet" href="style.css"></head>
    <body>
    <main><section class="card">
      <p>指定されたスレッドは見つかりませんでした(削除された可能性があります)。</p>
      <p><a href="index.php">&laquo; 板一覧に戻る</a></p>
    </section></main>
    </body></html>
    <?php
    exit;
}

if (isset($_GET['posted'])) {
    $successMessage = 'レスを投稿しました。';
} elseif (isset($_GET['deleted'])) {
    $successMessage = '削除しました。';
} elseif (($_GET['error'] ?? '') === 'delete_failed') {
    $errors[] = '削除用パスワードが正しくないか、対象が見つかりませんでした。';
} elseif (($_GET['error'] ?? '') === 'locked') {
    $errors[] = '削除の試行回数が多すぎます。しばらく時間をおいてから再度お試しください。';
}

/* ------------------------------------------------------------
 * レス一覧の取得(ページネーション)
 * 1ページ目はOP(レス1)を含み、以降 BBS_RES_PER_PAGE 件ずつ表示する
 * ------------------------------------------------------------ */
$resCount = (int)$thread['res_count'];
$perPage = BBS_RES_PER_PAGE;
$totalPages = max(1, (int)ceil($resCount / $perPage));

$page = bbs_get_page_param();
if ($page > $totalPages) {
    $page = $totalPages;
}

$rangeStart = ($page - 1) * $perPage + 1;
$rangeEnd = $page * $perPage;
$repliesLo = max(2, $rangeStart);

$replies = [];
if ($repliesLo <= $rangeEnd) {
    $stmt = $pdo->prepare(
        'SELECT id, res_number, name, mail, comment, created_at FROM replies
         WHERE thread_id = :tid AND res_number BETWEEN :lo AND :hi ORDER BY res_number ASC'
    );
    $stmt->execute([':tid' => $threadId, ':lo' => $repliesLo, ':hi' => $rangeEnd]);
    $replies = $stmt->fetchAll();
}

$showOp = ($rangeStart <= 1);

$csrfToken = bbs_csrf_token();
$formToken = bbs_form_timing_token();
$isFull = $resCount >= BBS_MAX_RES;
$needsPostPassword = !bbs_is_post_unlocked($pdo);
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($thread['title']) ?> - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="site-header">
  <h1><?= h($thread['title']) ?></h1>
</header>

<main>
  <p><a href="index.php">&laquo; 板一覧に戻る</a></p>

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
    <?php if ($showOp): ?>
      <div class="post op" id="res-1">
        <div class="post-meta">
          <span class="res-number">1</span>
          <span class="name"><?= h($thread['name']) ?></span>
          <?php if ($thread['mail'] !== ''): ?><span class="mail">[<?= h($thread['mail']) ?>]</span><?php endif; ?>
          ・<?= h(date('Y-m-d H:i:s', (int)$thread['created_at'])) ?>
        </div>
        <div class="post-body"><?= bbs_nl2br_safe(bbs_linkify_anchors(h($thread['comment']))) ?></div>
        <?= bbs_render_delete_form('thread', (int)$thread['id'], $csrfToken) ?>
      </div>
    <?php endif; ?>

    <?php foreach ($replies as $r): ?>
      <div class="post" id="res-<?= (int)$r['res_number'] ?>">
        <div class="post-meta">
          <span class="res-number"><?= (int)$r['res_number'] ?></span>
          <span class="name"><?= h($r['name']) ?></span>
          <?php if ($r['mail'] !== ''): ?><span class="mail">[<?= h($r['mail']) ?>]</span><?php endif; ?>
          ・<?= h(date('Y-m-d H:i:s', (int)$r['created_at'])) ?>
        </div>
        <div class="post-body"><?= bbs_nl2br_safe(bbs_linkify_anchors(h($r['comment']))) ?></div>
        <?= bbs_render_delete_form('reply', (int)$r['id'], $csrfToken, $threadId) ?>
      </div>
    <?php endforeach; ?>

    <?php if ($totalPages > 1): ?>
      <div class="pagination">
        <?php for ($p = 1; $p <= $totalPages; $p++): ?>
          <?php if ($p === $page): ?>
            <span class="current"><?= $p ?></span>
          <?php else: ?>
            <a href="thread.php?id=<?= $threadId ?>&page=<?= $p ?>"><?= $p ?></a>
          <?php endif; ?>
        <?php endfor; ?>
      </div>
    <?php endif; ?>
  </section>

  <section class="card">
    <h2>レスを書き込む</h2>
    <?php if ($isFull): ?>
      <p>このスレッドは上限レス数(<?= BBS_MAX_RES ?>)に達したため、書き込みできません。</p>
    <?php else: ?>
    <form method="post" action="thread.php?id=<?= $threadId ?>" autocomplete="off">
      <input type="hidden" name="action" value="new_reply">
      <input type="hidden" name="thread_id" value="<?= $threadId ?>">
      <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
      <input type="hidden" name="form_token" value="<?= h($formToken) ?>">

      <div class="field hp-field" aria-hidden="true">
        <label for="website">Webサイト(空欄のままにしてください)</label>
        <input type="text" id="website" name="website" tabindex="-1" autocomplete="off">
      </div>

      <div class="row2">
        <div class="field">
          <label for="name">お名前(任意・「名前#トリップ鍵」でトリップ表示可)</label>
          <input type="text" id="name" name="name" maxlength="<?= BBS_NAME_MAX ?>" placeholder="名無しさん">
        </div>
        <div class="field">
          <label for="mail">メール欄(sageで下げ進行)</label>
          <input type="text" id="mail" name="mail" maxlength="<?= BBS_MAIL_MAX ?>" placeholder="sage">
        </div>
      </div>

      <div class="field">
        <label for="comment">本文(必須・<?= BBS_COMMENT_MAX ?>文字以内)</label>
        <textarea id="comment" name="comment" maxlength="<?= BBS_COMMENT_MAX ?>" required></textarea>
      </div>

      <div class="field">
        <label for="password">削除用パスワード(任意)</label>
        <input type="password" id="password" name="password" maxlength="<?= BBS_PASSWORD_MAX ?>" autocomplete="new-password">
      </div>

      <?php if ($needsPostPassword): ?>
      <div class="field">
        <label for="site_post_password">投稿用パスワード(必須・管理人から共有されたパスワードを入力)</label>
        <input type="password" id="site_post_password" name="site_post_password" maxlength="<?= BBS_PASSWORD_MAX ?>" autocomplete="off" required>
      </div>
      <?php endif; ?>

      <button type="submit">レスする</button>
    </form>
    <?php endif; ?>
  </section>
</main>

<footer>
  <?= h(BBS_SITE_NAME) ?> &mdash; <a href="admin/login.php">管理者ログイン</a>
</footer>
</body>
</html>
