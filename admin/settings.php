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

$errors = [];
$successMessage = null;

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {

    if (!bbs_csrf_verify($_POST['csrf_token'] ?? null)) {
        $errors[] = '不正なリクエストです。ページを再読み込みしてもう一度お試しください。';
    } else {
        $viewEnabled = isset($_POST['view_password_enabled']);
        $postEnabled = isset($_POST['post_password_enabled']);

        $newViewPw = bbs_clean_text((string)($_POST['new_view_password'] ?? ''), BBS_PASSWORD_MAX);
        $newPostPw = bbs_clean_text((string)($_POST['new_post_password'] ?? ''), BBS_PASSWORD_MAX);

        if ($newViewPw === null || $newPostPw === null) {
            $errors[] = 'パスワードが長すぎるか、使用できない文字が含まれています。';
        } else {
            bbs_set_setting($pdo, 'view_password_enabled', $viewEnabled ? '1' : '0');
            bbs_set_setting($pdo, 'post_password_enabled', $postEnabled ? '1' : '0');

            if ($newViewPw !== '') {
                bbs_set_setting($pdo, 'view_password_hash', password_hash($newViewPw, PASSWORD_DEFAULT));
            }
            if ($newPostPw !== '') {
                bbs_set_setting($pdo, 'post_password_hash', password_hash($newPostPw, PASSWORD_DEFAULT));
            }

            if ($viewEnabled && bbs_get_setting($pdo, 'view_password_hash', '') === '') {
                $errors[] = '閲覧用パスワードが未設定のため有効化できません。パスワードを入力して保存してください。';
                bbs_set_setting($pdo, 'view_password_enabled', '0');
            }
            if ($postEnabled && bbs_get_setting($pdo, 'post_password_hash', '') === '') {
                $errors[] = '投稿用パスワードが未設定のため有効化できません。パスワードを入力して保存してください。';
                bbs_set_setting($pdo, 'post_password_enabled', '0');
            }

            if (empty($errors)) {
                $successMessage = '設定を保存しました。パスワードを変更した場合、既存の閲覧・投稿中のセッションは再度パスワード入力が必要になります。';
            }
        }
    }
    bbs_csrf_rotate();
}

$viewEnabledNow = bbs_get_setting_bool($pdo, 'view_password_enabled');
$postEnabledNow = bbs_get_setting_bool($pdo, 'post_password_enabled');
$viewHasPassword = bbs_get_setting($pdo, 'view_password_hash', '') !== '';
$postHasPassword = bbs_get_setting($pdo, 'post_password_hash', '') !== '';
$csrfToken = bbs_csrf_token();
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>閲覧・投稿パスワード設定 - <?= h(BBS_SITE_NAME) ?></title>
<link rel="stylesheet" href="../style.css">
</head>
<body>
<header class="site-header"><h1>閲覧・投稿パスワード設定</h1></header>
<main>
  <p>
    <a href="index.php">&laquo; スレッド一覧に戻る</a> ・
    <a href="../index.php">掲示板に戻る</a> ・
    <a href="logout.php">ログアウト</a>
  </p>

  <?php if ($successMessage !== null): ?>
    <div class="notice ok"><?= h($successMessage) ?></div>
  <?php endif; ?>
  <?php if (!empty($errors)): ?>
    <div class="notice error">
      <?php foreach ($errors as $e): ?><div><?= h($e) ?></div><?php endforeach; ?>
    </div>
  <?php endif; ?>

  <section class="card">
    <h2>閲覧パスワード</h2>
    <p>有効にすると、管理者以外は掲示板を見る前にパスワード入力が必要になります。</p>
    <p>現在の状態: <strong><?= $viewEnabledNow ? '有効' : '無効' ?></strong>
      (パスワード<?= $viewHasPassword ? '設定済み' : '未設定' ?>)</p>
  </section>

  <section class="card">
    <h2>投稿パスワード</h2>
    <p>有効にすると、スレッド作成・レス投稿の際にパスワード入力が必要になります(一度正しく入力すればそのセッション内は再入力不要)。</p>
    <p>現在の状態: <strong><?= $postEnabledNow ? '有効' : '無効' ?></strong>
      (パスワード<?= $postHasPassword ? '設定済み' : '未設定' ?>)</p>
  </section>

  <section class="card">
    <h2>設定の変更</h2>
    <form method="post" action="settings.php" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= h($csrfToken) ?>">

      <div class="field">
        <label>
          <input type="checkbox" name="view_password_enabled" value="1" <?= $viewEnabledNow ? 'checked' : '' ?>>
          閲覧パスワードを有効にする
        </label>
      </div>
      <div class="field">
        <label for="new_view_password">閲覧パスワードを変更する(空欄なら現在の設定を維持)</label>
        <input type="password" id="new_view_password" name="new_view_password" maxlength="<?= BBS_PASSWORD_MAX ?>" autocomplete="new-password" placeholder="新しい閲覧パスワード">
      </div>

      <hr>

      <div class="field">
        <label>
          <input type="checkbox" name="post_password_enabled" value="1" <?= $postEnabledNow ? 'checked' : '' ?>>
          投稿パスワードを有効にする
        </label>
      </div>
      <div class="field">
        <label for="new_post_password">投稿パスワードを変更する(空欄なら現在の設定を維持)</label>
        <input type="password" id="new_post_password" name="new_post_password" maxlength="<?= BBS_PASSWORD_MAX ?>" autocomplete="new-password" placeholder="新しい投稿パスワード">
      </div>

      <p class="notice" style="background:#fff7ed;color:#9a3412;border:1px solid #fed7aa;">
        パスワードを変更すると、既にパスワードを入力済みの利用者(管理者を除く)も
        再入力が必要になります。有効にする際は、必ずパスワードを一緒に設定してください。
      </p>

      <button type="submit">保存する</button>
    </form>
  </section>
</main>
</body>
</html>
