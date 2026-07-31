<?php
declare(strict_types=1);

require_once __DIR__ . '/lib.php';

bbs_send_security_headers();
bbs_start_session();
$pdo = bbs_get_pdo();

// 閲覧制限が無効ならこのページ自体不要なのでトップへ
if (bbs_is_view_unlocked($pdo)) {
    $target = bbs_sanitize_redirect_target($_GET['redirect'] ?? null);
    header('Location: ' . $target);
    exit;
}

$redirectTarget = bbs_sanitize_redirect_target($_GET['redirect'] ?? ($_POST['redirect'] ?? null));
$error = null;

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
        $error = '不正なリクエストです。ページを再読み込みしてもう一度お試しください。';
    } else {
        $ipHash = bbs_ip_hash(bbs_client_ip());
        $lockKey = 'viewgate:' . $ipHash;
        if (bbs_admin_is_locked($pdo, $lockKey)) {
            $error = '試行回数が多すぎます。しばらく時間をおいてから再度お試しください。';
        } else {
            $currentHash = bbs_get_setting($pdo, 'view_password_hash', '');
            $input = (string)($_POST['password'] ?? '');
            $ok = ($currentHash !== '' && $input !== '' && password_verify($input, $currentHash));

            bbs_admin_record_attempt($pdo, $lockKey, $ok);

            if ($ok) {
                $_SESSION['view_unlocked_hash'] = $currentHash;
                bbs_csrf_rotate();
                header('Location: ' . $redirectTarget);
                exit;
            }
            $error = 'パスワードが正しくありません。';
        }
    }
    bbs_csrf_rotate();
}

$csrfToken = bbs_csrf_token();
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>閲覧パスワード - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="site-header"><h1><?= h(BBS_SITE_NAME) ?></h1></header>
<main>
  <section class="card">
    <h2>この掲示板は閲覧にパスワードが必要です</h2>
    <?php if ($error !== null): ?>
      <div class="notice error"><?= h($error) ?></div>
    <?php endif; ?>
    <form method="post" action="gate.php" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
      <input type="hidden" name="redirect" value="<?= h($redirectTarget) ?>">
      <div class="field">
        <label for="password">閲覧パスワード</label>
        <input type="password" id="password" name="password" autocomplete="off" required autofocus>
      </div>
      <button type="submit">閲覧する</button>
    </form>
  </section>
</main>
</body>
</html>
