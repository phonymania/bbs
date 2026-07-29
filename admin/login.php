<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib.php';

bbs_send_security_headers();
bbs_start_session();
$pdo = bbs_get_pdo();

if (!empty($_SESSION['is_admin'])) {
    header('Location: index.php');
    exit;
}

$error = null;
$ipHash = bbs_ip_hash(bbs_client_ip());

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {

    if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
        $error = '不正なリクエストです。ページを再読み込みしてもう一度お試しください。';
    } elseif (bbs_admin_is_locked($pdo, 'login:' . $ipHash)) {
        $error = 'ログイン試行回数が多すぎます。しばらく時間をおいてから再度お試しください。';
    } else {
        $password = (string)($_POST['password'] ?? '');
        // password_verify はタイミングセーフな比較を内部で行う
        $ok = ($password !== '') && password_verify($password, BBS_ADMIN_PASSWORD_HASH);

        bbs_admin_record_attempt($pdo, 'login:' . $ipHash, $ok);

        if ($ok) {
            session_regenerate_id(true); // 認証成功時は必ずセッションIDを再発行(セッション固定対策)
            $_SESSION['is_admin'] = true;
            $_SESSION['_started_at'] = time();
            bbs_csrf_rotate();
            header('Location: index.php');
            exit;
        }
        $error = 'パスワードが正しくありません。';
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
<title>管理者ログイン - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="../style.css">
</head>
<body>
<header class="site-header"><h1>管理者ログイン</h1></header>
<main>
  <?php if ($error !== null): ?>
    <div class="notice error"><?= h($error) ?></div>
  <?php endif; ?>
  <section class="card">
    <form method="post" action="login.php" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">
      <div class="field">
        <label for="password">管理者パスワード</label>
        <input type="password" id="password" name="password" autocomplete="current-password" required>
      </div>
      <button type="submit">ログイン</button>
    </form>
  </section>
  <p><a href="../index.php">&laquo; 掲示板に戻る</a></p>
</main>
</body>
</html>
