<?php
declare(strict_types=1);

require_once __DIR__ . '/../lib.php';

bbs_send_security_headers();
bbs_start_session();

// セッション変数を空にし、セッションを破棄したうえでCookieも削除する
$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        [
            'expires'  => time() - 42000,
            'path'     => $params['path'],
            'domain'   => $params['domain'],
            'secure'   => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'],
        ]
    );
}

session_destroy();

header('Location: login.php');
exit;
