<?php
/**
 * 開発用ルーター(PHP内蔵サーバー専用)
 * -------------------------------------------------------------
 * 使い方: php -S 127.0.0.1:8000 router.php
 *
 * 本番のApache環境では、この機能は .htaccess の RewriteRule で
 * 実現しているため、このファイルは不要(参照されない)。
 *
 * ChMate等の専用ブラウザは以下のような「見た目上のパス」で
 * アクセスしてくるため、それを実体の chmate/*.php にマッピングする。
 *   /{板ID}/subject.txt
 *   /{板ID}/SETTING.TXT
 *   /{板ID}/dat/{スレッドID}.dat
 *   /test/bbs.cgi
 */

declare(strict_types=1);

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = $uri === false || $uri === null ? '/' : rawurldecode($uri);

if (preg_match('#^/([^/]+)/subject\.txt$#', $uri, $m) === 1) {
    $_GET['board'] = $m[1];
    require __DIR__ . '/chmate/subject.php';
    return true;
}

if (preg_match('#^/([^/]+)/SETTING\.TXT$#i', $uri, $m) === 1) {
    $_GET['board'] = $m[1];
    require __DIR__ . '/chmate/setting.php';
    return true;
}

if (preg_match('#^/([^/]+)/dat/([0-9]+)\.dat$#', $uri, $m) === 1) {
    $_GET['board'] = $m[1];
    $_GET['id'] = $m[2];
    require __DIR__ . '/chmate/dat.php';
    return true;
}

if ($uri === '/test/bbs.cgi') {
    require __DIR__ . '/chmate/bbscgi.php';
    return true;
}

// それ以外は通常どおりPHP内蔵サーバーに処理させる(index.php等の静的/PHPファイル)
return false;
