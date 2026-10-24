<?php
declare(strict_types=1);
/**
 * 云湖防盗链图片下载器 · index.php
 * ------------------------------------------------------------
 * 一个独立的小工具，不依赖任何其他项目。
 *
 * 背景：云湖的图片服务器（chat-img*.jwznb.com）校验 Referer，
 *       浏览器直接打开图片地址、或右键「图片另存为」，一律返回 403。
 *       只有 Referer 属于云湖主域（*.jwzhd.com）白名单时才放行。
 *
 * 本工具由服务端带着合法 Referer 去取图，再原样吐给浏览器，
 * 因此不需要装任何插件、也不用改浏览器设置。
 *
 * 用法：
 *   网页版：双击「启动下载器.cmd」
 *           或 php -S 127.0.0.1:8910  然后打开 http://127.0.0.1:8910/
 *   命令行：php index.php <图片地址> [更多地址...]
 *           php index.php -f urls.txt       # 从文件读（一行一个，可混杂文本）
 *
 * 零依赖：只用 curl + json（PHP 未装 zip 扩展时，打包用的是手写的 ZIP 写入器）。
 */

/* ==================== 运行环境 ==================== */
// 兼容 PHP 7.4：下面三个函数是 PHP 8.0 才引入的
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $h, string $n): bool
    {
        return $n === '' || strncmp($h, $n, strlen($n)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $h, string $n): bool
    {
        if ($n === '') return true;
        $l = strlen($n);
        return $l <= strlen($h) && substr($h, -$l) === $n;
    }
}
if (!function_exists('str_contains')) {
    function str_contains(string $h, string $n): bool
    {
        return $n === '' || strpos($h, $n) !== false;
    }
}

@set_time_limit(180);
@ini_set('memory_limit', '256M');
@ini_set('display_errors', '0');   // 线上不要把 PHP 报错混进 JSON 响应，错误仍进日志

/* ==================== 配置 ==================== */
// 默认值；线上要改的放在同目录 config.php 里，避免升级主程序时被覆盖
$CFG = [
    // 云湖图片服务器的 Referer 白名单：必须是 *.jwzhd.com 下的地址
    'referer'    => 'https://chat-go.jwzhd.com/',
    'ua'         => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  . '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
    // 允许抓取的域名后缀（防止本工具变成任意 URL 的开放代理）
    'allow_host' => ['jwznb.com', 'jwzhd.com'],
    'password'   => '',                 // 访问口令；空 = 不校验
    'access_key' => '',                 // URL 密钥；空 = 不校验（见 config.php 说明）
    'max_bytes'  => 20 * 1024 * 1024,   // 单张上限 20MB
    'max_urls'   => 200,                // 单次最多处理多少个链接
    'cache_days' => 7,                  // 缓存保留天数
    'timeout'    => 25,
    'conc'       => 6,                  // 并发数
    'dir'        => __DIR__ . '/cache', // 缓存目录（固定，不允许被外部配置改到别处）
];

// 读取同目录 config.php（存在则覆盖默认值）
if (is_file(__DIR__ . '/config.php')) {
    $userCfg = @include __DIR__ . '/config.php';
    if (is_array($userCfg)) {
        foreach ($userCfg as $k => $v) {
            if ($k === 'dir') continue;   // 缓存目录不接受外部指定
            $CFG[$k] = $v;
        }
    }
}

// 缓存目录：不存在则创建，并记录是否可写（线上常见的坑就是这里没权限）
if (!is_dir($CFG['dir'])) @mkdir($CFG['dir'], 0755, true);
$CFG['dir_ok'] = is_dir($CFG['dir']) && is_writable($CFG['dir']);

/* ==================== 会话（口令登录用） ==================== */
if (session_status() === PHP_SESSION_NONE) {
    @session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Lax',
        'secure'   => !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off',
    ]);
    @session_start();
}
$CFG['session_ok'] = session_status() === PHP_SESSION_ACTIVE;

/** 是否启用了任何访问保护（口令或 URL 密钥）。 */
function imgdl_guarded(): bool
{
    global $CFG;
    return (string)($CFG['password'] ?? '') !== '' || (string)($CFG['access_key'] ?? '') !== '';
}

/** URL 密钥对应的 cookie 值（HMAC，无法伪造）。 */
function imgdl_key_token(string $key): string
{
    return hash_hmac('sha256', 'imgdl-access-v1', $key);
}

/**
 * 当前请求是否已通过访问校验。
 * 没有任何保护配置时恒为 true（打开即用）。
 */
function imgdl_auth_ok(): bool
{
    global $CFG;

    $pw  = (string)($CFG['password'] ?? '');
    $key = (string)($CFG['access_key'] ?? '');

    if ($pw === '' && $key === '') return true;          // 完全开放

    if ($pw !== '' && !empty($_SESSION['imgdl_auth'])) return true;   // 口令登录态

    if ($key !== '') {
        // ① 浏览器记住的 cookie
        $ck = (string)($_COOKIE['imgdl_k'] ?? '');
        if ($ck !== '' && hash_equals(imgdl_key_token($key), $ck)) return true;
        // ② 本次请求刚带了正确的 k（cookie 已下发，下一个请求生效）
        $got = (string)($_GET['k'] ?? '');
        if ($got !== '' && hash_equals($key, $got)) return true;
    }

    return false;
}

/* ---- URL 密钥：?k=xxx 访问一次，浏览器记住 90 天，随后把地址里的 k 去掉 ---- */
if ((string)($CFG['access_key'] ?? '') !== '' && (string)($_GET['k'] ?? '') !== '') {
    $gotKey = (string)$_GET['k'];
    if (hash_equals((string)$CFG['access_key'], $gotKey)) {
        setcookie('imgdl_k', imgdl_key_token((string)$CFG['access_key']), [
            'expires'  => time() + 86400 * 90,
            'path'     => '/',
            'httponly' => true,
            'samesite' => 'Lax',
            'secure'   => !empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off',
        ]);
        // 去掉 k 再跳转，别把密钥留在地址栏和浏览历史里
        $qs = $_GET;
        unset($qs['k']);
        $to = './' . ($qs ? ('?' . http_build_query($qs)) : '');
        header('Location: ' . $to, true, 302);
        exit;
    }
}


/* ==================== 工具函数 ==================== */

/** 域名是否命中白名单（按后缀匹配，含子域）。 */
function imgdl_host_ok(string $host, array $allow): bool
{
    $host = strtolower(trim($host));
    if ($host === '') return false;
    foreach ($allow as $sfx) {
        $sfx = strtolower(trim($sfx));
        if ($sfx === '') continue;
        if ($host === $sfx || str_ends_with($host, '.' . $sfx)) return true;
    }
    return false;
}

/**
 * 校验地址。返回 [是否可用, 错误文案, 是否应静默跳过]。
 * 非云湖域名标记为 skip（不当作失败展示，只统计忽略数量）。
 */
function imgdl_check_url(string $url): array
{
    global $CFG;
    $url = trim($url);
    if ($url === '') return [false, '空地址', false];
    $p = @parse_url($url);
    if (!is_array($p) || empty($p['scheme']) || empty($p['host'])) {
        return [false, '地址格式无效', false];
    }
    $scheme = strtolower((string)$p['scheme']);
    if ($scheme !== 'http' && $scheme !== 'https') {
        return [false, '仅支持 http/https', false];
    }
    if (!imgdl_host_ok((string)$p['host'], $CFG['allow_host'])) {
        return [false, '非云湖域名，已忽略', true];
    }
    return [true, '', false];
}

/** 缓存键：URL 的短哈希，同时用作文件名前缀。 */
function imgdl_key(string $url): string
{
    return substr(md5($url), 0, 16);
}

/** 从 URL 里猜一个像样的文件名（不含扩展名）。 */
function imgdl_basename(string $url): string
{
    $p = @parse_url($url);
    $base = $p ? basename((string)($p['path'] ?? '')) : '';
    $base = rawurldecode($base);
    $base = preg_replace('/[^\p{L}\p{N}._\-]+/u', '_', $base) ?? '';
    $base = trim($base, '._-');
    if ($base === '') $base = 'image';
    // 去掉已有扩展名，后面按真实类型补
    $base = preg_replace('/\.(jpe?g|png|gif|webp|bmp|avif|svg)$/i', '', $base) ?? $base;
    if ($base === '') $base = 'image';
    return mb_substr($base, 0, 60);
}

/** 从二进制头部嗅探图片类型（getimagesize 不认的格式靠这个兜底）。 */
function imgdl_sniff(string $d): array
{
    $head = substr($d, 0, 32);
    if (str_starts_with($head, "\xFF\xD8\xFF"))                        return ['jpeg', 'jpg',  'image/jpeg'];
    if (str_starts_with($head, "\x89PNG\r\n\x1A\n"))                    return ['png',  'png',  'image/png'];
    if (str_starts_with($head, 'GIF87a') || str_starts_with($head, 'GIF89a')) return ['gif', 'gif', 'image/gif'];
    if (str_starts_with($head, 'RIFF') && substr($d, 8, 4) === 'WEBP')  return ['webp', 'webp', 'image/webp'];
    if (str_starts_with($head, 'BM'))                                   return ['bmp',  'bmp',  'image/bmp'];
    if (substr($d, 4, 4) === 'ftyp' && preg_match('/avif|avis/', substr($d, 8, 12))) return ['avif', 'avif', 'image/avif'];
    if (preg_match('/<svg[\s>]/i', substr($d, 0, 512)))                return ['svg',  'svg',  'image/svg+xml'];
    return ['', '', ''];
}

/**
 * 拿图片真实类型与尺寸。
 * 先信 getimagesize（能给出宽高），失败再用文件头嗅探。
 */
function imgdl_inspect(string $body): array
{
    $mime = ''; $ext = ''; $w = 0; $h = 0;

    $info = @getimagesize('data://application/octet-stream;base64,' . base64_encode($body));
    if (is_array($info) && !empty($info['mime'])) {
        $mime = (string)$info['mime'];
        $w    = (int)($info[0] ?? 0);
        $h    = (int)($info[1] ?? 0);
        $map  = [
            'image/jpeg' => 'jpg', 'image/png' => 'png', 'image/gif' => 'gif',
            'image/webp' => 'webp', 'image/bmp' => 'bmp', 'image/avif' => 'avif',
            'image/svg+xml' => 'svg', 'image/x-icon' => 'ico',
        ];
        $ext = $map[strtolower($mime)] ?? '';
    }

    if ($ext === '') {
        [$t, $e, $m] = imgdl_sniff($body);
        if ($e !== '') { $ext = $e; $mime = $m; }
    }

    return ['mime' => $mime, 'ext' => $ext, 'w' => $w, 'h' => $h];
}

/** 人类可读体积。 */
function imgdl_size_cn(int $bytes): string
{
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1048576) return round($bytes / 1024, 1) . ' KB';
    return round($bytes / 1048576, 2) . ' MB';
}

/** 建一个统一配置的 curl 句柄（核心：带上云湖 Referer，破防盗链）。 */
function imgdl_new_handle(string $url)
{
    global $CFG;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER    => true,
        CURLOPT_FOLLOWLOCATION    => true,
        CURLOPT_MAXREDIRS         => 3,
        CURLOPT_CONNECTTIMEOUT    => 8,
        CURLOPT_TIMEOUT           => (int)$CFG['timeout'],
        CURLOPT_SSL_VERIFYPEER    => false,
        CURLOPT_SSL_VERIFYHOST    => 0,
        CURLOPT_USERAGENT         => $CFG['ua'],
        // ↓↓↓ 破防盗链的关键一行 ↓↓↓
        CURLOPT_REFERER           => $CFG['referer'],
        CURLOPT_HTTPHEADER        => [
            'Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Language: zh-CN,zh;q=0.9',
        ],
        CURLOPT_MAXFILESIZE       => (int)$CFG['max_bytes'],
    ]);
    return $ch;
}

/** 把下载到的二进制落盘并生成元数据。 */
function imgdl_save(string $url, string $body, array $httpInfo): array
{
    global $CFG;

    $bad = static fn(string $msg): array => ['ok' => false, 'url' => $url, 'err' => $msg];

    if (($httpInfo['err'] ?? 0) !== 0) {
        $map = [
            CURLE_OPERATION_TIMEDOUT => '请求超时',
            CURLE_COULDNT_RESOLVE_HOST => '域名解析失败',
            CURLE_COULDNT_CONNECT => '无法连接服务器',
            CURLE_SSL_CONNECT_ERROR => 'SSL 握手失败',
            CURLE_FILESIZE_EXCEEDED => '文件超过大小上限',
        ];
        return $bad($map[$httpInfo['err']] ?? ('网络错误 #' . $httpInfo['err']));
    }

    $code = (int)($httpInfo['code'] ?? 0);
    if ($code === 403) return $bad('被防盗链拦截（403）');
    if ($code === 404) return $bad('图片不存在（404）');
    if ($code !== 200) return $bad('服务器返回 HTTP ' . $code);

    if (!is_string($body) || $body === '') return $bad('响应为空');

    $len = strlen($body);
    if ($len > (int)$CFG['max_bytes']) return $bad('超过大小上限（' . imgdl_size_cn($len) . '）');

    $ins = imgdl_inspect($body);
    if ($ins['ext'] === '') {
        // 不是图片：多半是错误页 / 权限页
        $peek = trim(strip_tags(substr($body, 0, 300)));
        return $bad('返回的不是图片' . ($peek !== '' ? '：' . mb_substr($peek, 0, 60) : ''));
    }

    $key  = imgdl_key($url);
    $file = $key . '.' . $ins['ext'];
    $path = $CFG['dir'] . '/' . $file;

    if (@file_put_contents($path, $body, LOCK_EX) === false) {
        return $bad('写入缓存失败，请检查目录权限');
    }

    $meta = [
        'ok'    => true,
        'url'   => $url,
        'key'   => $key,
        'file'  => $file,
        'name'  => imgdl_basename($url) . '.' . $ins['ext'],
        'mime'  => $ins['mime'],
        'ext'   => $ins['ext'],
        'w'     => $ins['w'],
        'h'     => $ins['h'],
        'bytes' => $len,
        'size'  => imgdl_size_cn($len),
        'ts'    => time(),
    ];
    @file_put_contents($CFG['dir'] . '/' . $key . '.json', json_encode($meta, JSON_UNESCAPED_UNICODE), LOCK_EX);

    return $meta;
}

/** 读缓存元数据；命中且文件还在才返回，否则 null。 */
function imgdl_meta_cached(string $url): ?array
{
    global $CFG;
    $key   = imgdl_key($url);
    $metaF = $CFG['dir'] . '/' . $key . '.json';
    if (!is_file($metaF)) return null;
    $m = json_decode((string)@file_get_contents($metaF), true);
    if (!is_array($m) || empty($m['file'])) return null;
    if (!is_file($CFG['dir'] . '/' . $m['file'])) return null;
    $m['ok']     = true;
    $m['cached'] = true;
    return $m;
}

/** 单张下载（先查缓存）。 */
function imgdl_fetch_one(string $url): array
{
    $hit = imgdl_meta_cached($url);
    if ($hit !== null) return $hit;

    $ch   = imgdl_new_handle($url);
    $body = curl_exec($ch);
    $info = [
        'code' => (int)curl_getinfo($ch, CURLINFO_HTTP_CODE),
        'type' => (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
        'err'  => (int)curl_errno($ch),
    ];
    curl_close($ch);

    return imgdl_save($url, is_string($body) ? $body : '', $info);
}

/**
 * 惰性清理缓存：按概率触发，避免每次请求都扫目录，也避免磁盘无限增长。
 */
function imgdl_gc(?int $days = null, int $prob = 20): void
{
    global $CFG;
    if (mt_rand(1, max(1, $prob)) !== 1) return;
    $days = $days ?? max(1, (int)($CFG['cache_days'] ?? 7));
    $cut  = time() - $days * 86400;
    foreach ((array)@glob($CFG['dir'] . '/*') as $f) {
        if (is_string($f) && is_file($f) && (int)@filemtime($f) < $cut) @unlink($f);
    }
}

/**
 * 批量下载（curl_multi 并发）。
 * 返回按输入顺序排列的结果数组，跳过项带 skip=true。
 */
function imgdl_fetch_many(array $urls, ?int $conc = null): array
{
    global $CFG;
    imgdl_gc();
    $conc = max(1, $conc ?? (int)$CFG['conc']);

    $results = [];   // url => result（保持插入顺序）
    $jobs    = [];

    foreach ($urls as $raw) {
        $u = trim((string)$raw);
        if ($u === '' || isset($results[$u]) || in_array($u, $jobs, true)) continue;

        [$ok, $err, $skip] = imgdl_check_url($u);
        if (!$ok) {
            $results[$u] = ['ok' => false, 'url' => $u, 'err' => $err, 'skip' => $skip];
            continue;
        }
        $hit = imgdl_meta_cached($u);
        if ($hit !== null) { $results[$u] = $hit; continue; }

        $jobs[] = $u;
    }

    if ($jobs) {
        $mh      = curl_multi_init();
        $map     = [];   // (int)$ch => url
        $queue   = $jobs;
        $total   = count($queue);
        $started = 0;
        $running = 0;

        while ($started < $total || $running > 0) {
            while ($running < $conc && $started < $total) {
                $u  = $queue[$started++];
                $ch = imgdl_new_handle($u);
                $map[(int)$ch] = $u;
                curl_multi_add_handle($mh, $ch);
                $running++;
            }

            do { $mrc = curl_multi_exec($mh, $active); }
            while ($mrc === CURLM_CALL_MULTI_PERFORM);

            while ($done = curl_multi_info_read($mh)) {
                $ch  = $done['handle'];
                $id  = (int)$ch;
                $u   = $map[$id] ?? '';
                $body = curl_multi_getcontent($ch);
                $info = [
                    'code' => (int)curl_getinfo($ch, CURLINFO_HTTP_CODE),
                    'type' => (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
                    'err'  => (int)$done['result'],
                ];
                curl_multi_remove_handle($mh, $ch);
                curl_close($ch);
                unset($map[$id]);
                $running--;

                if ($u !== '') {
                    $results[$u] = imgdl_save($u, is_string($body) ? $body : '', $info);
                }
            }

            if ($running > 0) curl_multi_select($mh, 0.4);
        }
        curl_multi_close($mh);
    }

    // 按输入顺序还原
    $ordered = [];
    foreach ($urls as $raw) {
        $u = trim((string)$raw);
        if ($u !== '' && isset($results[$u])) $ordered[] = $results[$u];
    }
    return $ordered;
}

/**
 * 手写 ZIP 打包（本机 PHP 无 zip 扩展）。
 * 有 gzdeflate 就走 deflate 压缩，否则存储模式。
 */
function imgdl_zip(array $items): string
{
    global $CFG;

    $local   = '';
    $central = '';
    $offset  = 0;
    $count   = 0;

    $now  = getdate();
    $dtime = (($now['hours'] << 11) | ($now['minutes'] << 5) | ($now['seconds'] >> 1)) & 0xFFFF;
    $ddate = ((($now['year'] - 1980) << 9) | ($now['mon'] << 5) | $now['mday']) & 0xFFFF;

    foreach ($items as $it) {
        $file = (string)($it['file'] ?? '');
        if ($file === '' || !preg_match('/^[a-f0-9]{16}\.[a-z0-9]{2,5}$/i', $file)) continue;

        $path = $CFG['dir'] . '/' . $file;
        if (!is_file($path)) continue;

        $data = (string)@file_get_contents($path);
        if ($data === '') continue;

        $name = (string)($it['name'] ?? $file);
        $name = preg_replace('/[\\\\\/:*?"<>|\x00-\x1F]/u', '_', $name) ?? $file;
        if ($name === '') $name = $file;
        // 同名去重
        $name = sprintf('%02d_%s', $count + 1, $name);

        $crc  = crc32($data);
        $usize = strlen($data);
        $comp = @gzdeflate($data, 6);
        if (is_string($comp) && $comp !== '' && strlen($comp) < $usize) {
            $method = 8;
            $csize  = strlen($comp);
            $payload = $comp;
        } else {
            $method  = 0;
            $csize   = $usize;
            $payload = $data;
        }

        $nlen = strlen($name);

        $lfh = pack(
            'VvvvvvVVVvv',
            0x04034b50, 20, 0x0800, $method, $dtime, $ddate,
            $crc, $csize, $usize, $nlen, 0
        ) . $name;

        $local .= $lfh . $payload;

        $central .= pack(
            'VvvvvvvVVVvvvvvVV',
            0x02014b50, 20, 20, 0x0800, $method, $dtime, $ddate,
            $crc, $csize, $usize, $nlen, 0, 0, 0, 0, 0, $offset
        ) . $name;

        $offset += strlen($lfh) + $csize;
        $count++;
    }

    if ($count === 0) return '';

    $eocd = pack(
        'VvvvvVVv',
        0x06054b50, 0, 0, $count, $count,
        strlen($central), strlen($local), 0
    );

    return $local . $central . $eocd;
}

/** 输出一个已缓存的图片文件（预览 / 单张下载共用）。 */
function imgdl_output_file(string $file, bool $asAttachment, string $downloadName = ''): bool
{
    global $CFG;

    if (!preg_match('/^[a-f0-9]{16}\.[a-z0-9]{2,5}$/i', $file)) return false;
    $path = $CFG['dir'] . '/' . $file;
    if (!is_file($path)) return false;

    $mime = 'application/octet-stream';
    $info = @getimagesize($path);
    if (is_array($info) && !empty($info['mime'])) {
        $mime = (string)$info['mime'];
    } else {
        [, , $m] = imgdl_sniff((string)@file_get_contents($path, false, null, 0, 512));
        if ($m !== '') $mime = $m;
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($path));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: ' . ($asAttachment ? 'no-store' : 'private, max-age=86400'));

    if ($asAttachment) {
        if ($downloadName === '') $downloadName = $file;
        header('Content-Disposition: attachment; filename*=UTF-8\'\'' . rawurlencode($downloadName));
    } else {
        // 预览：即使内容是 SVG 也不允许执行脚本
        header("Content-Security-Policy: default-src 'none'; sandbox");
    }

    readfile($path);
    return true;
}

/**
 * 从任意文本里提取所有 http(s) 链接。
 *
 * 用 RFC 3986 的「正向字符集」而不是排除法：全角标点（（）、，。“”）、中文、
 * 空格、"'"、markdown 的 ) 天然就不在集合里，不会像排除法那样漏掉全角括号
 * 导致把「url（正文）」整段当成地址。
 */
function imgdl_extract_urls(string $text): array
{
    $re = '#https?://[A-Za-z0-9\-._~:/?\#\[\]@!$&*+,;=%]+#i';
    if (!preg_match_all($re, $text, $m)) return [];

    $out = [];
    foreach ($m[0] as $u) {
        // 去掉结尾可能黏上的西文标点（句号/逗号/引号等）
        $u = rtrim($u, ".,;:!?'\"");
        if ($u === '' || !preg_match('#^https?://[^/]+#i', $u)) continue;
        $out[$u] = true;
    }
    return array_keys($out);
}

/* ==================== 命令行模式 ==================== */
if (PHP_SAPI === 'cli') {
    $argvList = array_slice($argv, 1);
    $urls     = [];

    foreach ($argvList as $a) {
        if ($a === '-f' || $a === '--file') continue;
    }
    $fi = array_search('-f', $argvList, true);
    if ($fi === false) $fi = array_search('--file', $argvList, true);

    if ($fi !== false) {
        $file = $argvList[$fi + 1] ?? '';
        if ($file === '' || !is_file($file)) {
            fwrite(STDERR, "找不到文件：$file\n");
            exit(1);
        }
        $urls = imgdl_extract_urls((string)file_get_contents($file));
    } else {
        $urls = imgdl_extract_urls(implode("\n", $argvList));
    }

    if (!$urls) {
        fwrite(STDOUT, "用法：\n  php index.php <图片地址> [更多地址...]\n  php index.php -f urls.txt\n");
        exit(1);
    }

    fwrite(STDOUT, "开始下载 " . count($urls) . " 个地址…\n\n");

    $res  = imgdl_fetch_many($urls);
    $ok   = 0; $fail = 0; $skip = 0; $bytes = 0;

    foreach ($res as $r) {
        if (!empty($r['skip'])) { $skip++; continue; }
        if (!empty($r['ok'])) {
            $ok++;
            $bytes += (int)($r['bytes'] ?? 0);
            fwrite(STDOUT, sprintf("  ✓ %-46s %s\n", mb_substr((string)$r['name'], 0, 44), (string)($r['size'] ?? '')));
        } else {
            $fail++;
            fwrite(STDOUT, sprintf("  ✗ %-46s %s\n", mb_substr((string)$r['url'], 0, 44), (string)($r['err'] ?? '失败')));
        }
    }

    fwrite(STDOUT, sprintf("\n完成：成功 %d / 失败 %d / 忽略 %d，共 %s\n", $ok, $fail, $skip, imgdl_size_cn($bytes)));
    fwrite(STDOUT, "文件位置：" . $CFG['dir'] . "\n");
    exit($fail > 0 && $ok === 0 ? 1 : 0);
}

/* ==================== 网页接口 ==================== */
$action = (string)($_GET['a'] ?? '');

if ($action !== '') {
    header('X-Content-Type-Options: nosniff');

    // ---- 登录 ----
    if ($action === 'login') {
        header('Content-Type: application/json; charset=utf-8');
        $pw = (string)($CFG['password'] ?? '');
        if ($pw === '') {
            echo json_encode(['ok' => true]);
            exit;
        }
        if (!$CFG['session_ok']) {
            echo json_encode(['ok' => false, 'error' => '服务器 session 不可用，无法启用口令保护'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // 简单限流：连续失败 5 次锁 10 分钟
        $f = $_SESSION['imgdl_fail'] ?? ['n' => 0, 'until' => 0];
        if ((int)$f['until'] > time()) {
            echo json_encode(['ok' => false, 'error' => '尝试过于频繁，请稍后再试'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $in = (string)($_POST['password'] ?? '');
        if ($in !== '' && hash_equals($pw, $in)) {
            session_regenerate_id(true);
            $_SESSION['imgdl_auth'] = true;
            $_SESSION['imgdl_fail'] = ['n' => 0, 'until' => 0];
            echo json_encode(['ok' => true]);
        } else {
            $f['n'] = (int)$f['n'] + 1;
            if ($f['n'] >= 5) { $f['n'] = 0; $f['until'] = time() + 600; }
            $_SESSION['imgdl_fail'] = $f;
            usleep(400000);   // 拖慢暴力尝试
            echo json_encode(['ok' => false, 'error' => '口令不正确'], JSON_UNESCAPED_UNICODE);
        }
        exit;
    }

    // ---- 退出 ----
    if ($action === 'logout') {
        $_SESSION = [];
        if ($CFG['session_ok']) @session_destroy();
        header('Location: ./');
        exit;
    }

    // ---- 其余接口一律先校验口令 ----
    if (!imgdl_auth_ok()) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => false, 'error' => '未登录', 'needLogin' => true], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ---- 批量解析并下载 ----
    if ($action === 'batch') {
        header('Content-Type: application/json; charset=utf-8');
        $raw  = (string)($_POST['text'] ?? '');
        $urls = imgdl_extract_urls($raw);

        if (!$urls) {
            echo json_encode(['ok' => false, 'error' => '没有识别到任何链接'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        // 单次数量上限，避免一个请求跑太久被主机掐断
        $maxUrls = max(1, (int)($CFG['max_urls'] ?? 200));
        $truncated = 0;
        if (count($urls) > $maxUrls) {
            $truncated = count($urls) - $maxUrls;
            $urls = array_slice($urls, 0, $maxUrls);
        }

        $t0  = microtime(true);
        $res = imgdl_fetch_many($urls);

        $okCnt = 0; $skipCnt = 0; $bytes = 0;
        $items = [];
        foreach ($res as $r) {
            if (!empty($r['skip'])) { $skipCnt++; continue; }
            if (!empty($r['ok'])) { $okCnt++; $bytes += (int)($r['bytes'] ?? 0); }
            $items[] = $r;
        }

        echo json_encode([
            'ok'      => true,
            'items'   => $items,
            'summary' => [
                'total'   => count($items),
                'success' => $okCnt,
                'fail'    => count($items) - $okCnt,
                'skipped' => $skipCnt,
                'bytes'   => $bytes,
                'size'    => imgdl_size_cn($bytes),
                'ms'      => (int)round((microtime(true) - $t0) * 1000),
                'truncated' => $truncated,   // 超过单次上限而没处理的链接数
            ],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ---- 预览原图 ----
    if ($action === 'raw') {
        $k = (string)($_GET['k'] ?? '');
        $m = json_decode((string)@file_get_contents($CFG['dir'] . '/' . preg_replace('/[^a-f0-9]/i', '', $k) . '.json'), true);
        $file = is_array($m) ? (string)($m['file'] ?? '') : '';
        if ($file === '' || !imgdl_output_file($file, false)) {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo '图片不存在或已被清理';
        }
        exit;
    }

    // ---- 单张下载 ----
    if ($action === 'dl') {
        $k = (string)($_GET['k'] ?? '');
        $m = json_decode((string)@file_get_contents($CFG['dir'] . '/' . preg_replace('/[^a-f0-9]/i', '', $k) . '.json'), true);
        $file = is_array($m) ? (string)($m['file'] ?? '') : '';
        $name = is_array($m) ? (string)($m['name'] ?? 'image') : 'image';
        if ($file === '' || !imgdl_output_file($file, true, $name)) {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo '图片不存在或已被清理';
        }
        exit;
    }

    // ---- 打包 ZIP ----
    if ($action === 'zip') {
        $keys = (string)($_GET['k'] ?? '');
        $list = array_filter(array_map('trim', explode(',', $keys)));
        if (!$list) {
            http_response_code(400);
            header('Content-Type: text/plain; charset=utf-8');
            echo '没有要打包的图片';
            exit;
        }

        $items = [];
        foreach ($list as $k) {
            $k = preg_replace('/[^a-f0-9]/i', '', $k);
            if ($k === '') continue;
            $m = json_decode((string)@file_get_contents($CFG['dir'] . '/' . $k . '.json'), true);
            if (is_array($m)) $items[] = $m;
        }

        $zip = imgdl_zip($items);
        if ($zip === '') {
            http_response_code(404);
            header('Content-Type: text/plain; charset=utf-8');
            echo '没有可打包的图片';
            exit;
        }

        $zipName = 'yunhu-images-' . date('Ymd-His') . '.zip';
        header('Content-Type: application/zip');
        header('Content-Length: ' . strlen($zip));
        header('Content-Disposition: attachment; filename="' . $zipName . '"');
        header('Cache-Control: no-store');
        echo $zip;
        exit;
    }

    // ---- 读取本程序目录下的 urls.txt（如果有的话），方便命令行/批量 ----
    if ($action === 'local') {
        header('Content-Type: application/json; charset=utf-8');
        $f = __DIR__ . '/urls.txt';
        if (!is_file($f)) {
            echo json_encode(['ok' => false, 'error' => '本程序目录下没有 urls.txt'], JSON_UNESCAPED_UNICODE);
            exit;
        }
        $urls = imgdl_extract_urls((string)@file_get_contents($f));
        if (!$urls) {
            echo json_encode(['ok' => false, 'error' => 'urls.txt 里没有识别到链接'], JSON_UNESCAPED_UNICODE);
            exit;
        }
        echo json_encode(['ok' => true, 'urls' => $urls, 'count' => count($urls)], JSON_UNESCAPED_UNICODE);
        exit;
    }

    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    echo '未知操作';
    exit;
}

/* ==================== 页面 ==================== */
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");

/* ---------- 未通过访问校验：口令页 / 密钥提示页 ---------- */
if (!imgdl_auth_ok()) {

    /* 只配了 URL 密钥、没配口令：提示用带 k 的完整地址进入 */
    if ((string)($CFG['password'] ?? '') === '') {
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>需要访问地址 · 云湖图片下载器</title>
<style>
  :root{ --bg:#f4f6fb; --card:#fff; --tx:#182132; --tx2:#6b7688; --line:#e6eaf2;
         --sh:0 1px 2px rgba(24,33,50,.04), 0 12px 32px rgba(24,33,50,.08); }
  @media (prefers-color-scheme: dark){
    :root{ --bg:#101319; --card:#181c25; --tx:#e7ecf5; --tx2:#8e99ab; --line:#252b37;
           --sh:0 1px 2px rgba(0,0,0,.4), 0 12px 36px rgba(0,0,0,.4); }
  }
  *{box-sizing:border-box}
  body{ margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg);
        color:var(--tx); padding:24px; text-align:center;
        font:14px/1.6 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif; }
  .box{ width:392px; max-width:100%; background:var(--card); border:1px solid var(--line);
        border-radius:16px; padding:34px 30px 30px; box-shadow:var(--sh); }
  .ico{ width:46px; height:46px; margin:0 auto 16px; border-radius:13px;
        background:linear-gradient(135deg,#5b86ff,#3b66e8); display:grid; place-items:center;
        box-shadow:0 6px 18px rgba(79,124,255,.35); }
  .ico svg{width:23px; height:23px; stroke:#fff; fill:none; stroke-width:2; stroke-linecap:round; stroke-linejoin:round}
  h1{font-size:17px; margin:0 0 8px}
  p{font-size:12.5px; color:var(--tx2); margin:0; line-height:1.7}
  code{ font-family:ui-monospace,Consolas,monospace; font-size:12px;
        background:rgba(79,124,255,.1); color:#3b66e8; padding:1px 6px; border-radius:5px; }
</style>
</head>
<body>
<div class="box">
  <div class="ico">
    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
  </div>
  <h1>需要完整访问地址</h1>
  <p>这个工具设了访问密钥，请用带 <code>?k=</code> 的完整链接打开一次，<br>之后浏览器会记住，直接打开即可。</p>
</div>
</body>
</html>
<?php
        exit;
    }

?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>需要口令 · 云湖图片下载器</title>
<style>
  :root{
    --bg:#f4f6fb; --card:#fff; --tx:#182132; --tx2:#6b7688; --tx3:#9aa4b4;
    --line:#e6eaf2; --acc:#4f7cff; --acc2:#3b66e8; --err:#ef4a4a;
    --sh:0 1px 2px rgba(24,33,50,.04), 0 12px 32px rgba(24,33,50,.08);
  }
  @media (prefers-color-scheme: dark){
    :root{ --bg:#101319; --card:#181c25; --tx:#e7ecf5; --tx2:#8e99ab; --tx3:#697384;
           --line:#252b37; --sh:0 1px 2px rgba(0,0,0,.4), 0 12px 36px rgba(0,0,0,.4); }
  }
  *{box-sizing:border-box}
  body{
    margin:0; min-height:100vh; display:grid; place-items:center; background:var(--bg);
    color:var(--tx); padding:24px;
    font:14px/1.6 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  form{
    width:352px; max-width:100%; background:var(--card); border:1px solid var(--line);
    border-radius:16px; padding:34px 30px 28px; box-shadow:var(--sh); text-align:center;
  }
  .ico{
    width:46px; height:46px; margin:0 auto 16px; border-radius:13px;
    background:linear-gradient(135deg,#5b86ff,#3b66e8); display:grid; place-items:center;
    box-shadow:0 6px 18px rgba(79,124,255,.35);
  }
  .ico svg{width:23px; height:23px; stroke:#fff; fill:none; stroke-width:2; stroke-linecap:round; stroke-linejoin:round}
  h1{font-size:17px; margin:0 0 6px; letter-spacing:-.2px}
  .s{font-size:12.5px; color:var(--tx2); margin:0 0 22px}
  input{
    width:100%; padding:11px 14px; font-size:14px; color:var(--tx);
    background:transparent; border:1px solid var(--line); border-radius:10px;
    outline:none; transition:border-color .15s, box-shadow .15s;
  }
  input:focus{border-color:var(--acc); box-shadow:0 0 0 3px rgba(79,124,255,.15)}
  button{
    width:100%; margin-top:11px; padding:11px; border:0; border-radius:10px; cursor:pointer;
    background:var(--acc); color:#fff; font-size:14px; font-weight:500;
    box-shadow:0 4px 14px rgba(79,124,255,.3); transition:.15s;
  }
  button:hover:not(:disabled){background:var(--acc2)}
  button:disabled{opacity:.6; cursor:not-allowed}
  .err{min-height:18px; margin:11px 0 0; font-size:12.5px; color:var(--err)}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <div class="ico">
    <svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
  </div>
  <h1>需要访问口令</h1>
  <p class="s">此工具会消耗服务器带宽，仅限授权使用</p>
  <input type="password" id="p" placeholder="请输入口令" autocomplete="current-password" autofocus>
  <button type="submit" id="b">进入</button>
  <p class="err" id="e"></p>
</form>
<script>
const f = document.getElementById('f'), p = document.getElementById('p'),
      b = document.getElementById('b'), e = document.getElementById('e');

f.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const v = p.value.trim();
  if (!v) { e.textContent = '请输入口令'; p.focus(); return; }

  b.disabled = true; b.textContent = '验证中…'; e.textContent = '';
  try {
    const fd = new FormData();
    fd.append('password', v);
    const r = await fetch('?a=login', { method: 'POST', body: fd });
    const j = await r.json();
    if (j.ok) { location.reload(); return; }
    e.textContent = j.error || '口令不正确';
  } catch (err) {
    e.textContent = '网络错误，请重试';
  }
  b.disabled = false; b.textContent = '进入';
  p.select();
});
</script>
</body>
</html>
<?php
    exit;
}

// 部署自检：只报真正会让功能坏掉的问题，不打扰日常使用
$warns = [];
if (empty($CFG['dir_ok'])) {
    $warns[] = ['err', '<code>cache/</code> 目录不可写，下载会全部失败。请把该目录权限设为 755（个别主机需要 777），或手动创建它。'];
}
if (empty($CFG['session_ok']) && (string)($CFG['password'] ?? '') !== '') {
    $warns[] = ['err', '服务器 session 不可用，口令登录状态无法保持。请检查 PHP 的 session 配置。'];
}

// 完全没设保护（默认状态）：页面照常用，只在页脚留一句说明
$unguarded = (string)($CFG['password'] ?? '') === '' && (string)($CFG['access_key'] ?? '') === '';

// 若程序目录下放了 urls.txt，页面上会给个一键载入的入口
$localCount = 0;
$lf = __DIR__ . '/urls.txt';
if (is_file($lf)) {
    $localCount = count(imgdl_extract_urls((string)@file_get_contents($lf)));
}
?><!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>云湖防盗链图片下载器</title>
<style>
  :root{
    --bg:#f4f6fb; --card:#fff; --tx:#182132; --tx2:#6b7688; --tx3:#9aa4b4;
    --line:#e6eaf2; --acc:#4f7cff; --acc2:#3b66e8; --ok:#12b886; --err:#ef4a4a; --warn:#f0a020;
    --sh:0 1px 2px rgba(24,33,50,.04), 0 8px 24px rgba(24,33,50,.06);
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#101319; --card:#181c25; --tx:#e7ecf5; --tx2:#8e99ab; --tx3:#697384;
      --line:#252b37; --sh:0 1px 2px rgba(0,0,0,.4), 0 8px 28px rgba(0,0,0,.35);
    }
  }
  /* ?theme=dark / light 可强制指定，优先级高于系统偏好 */
  html[data-theme="dark"]{
    --bg:#101319; --card:#181c25; --tx:#e7ecf5; --tx2:#8e99ab; --tx3:#697384;
    --line:#252b37; --sh:0 1px 2px rgba(0,0,0,.4), 0 8px 28px rgba(0,0,0,.35);
  }
  html[data-theme="light"]{
    --bg:#f4f6fb; --card:#fff; --tx:#182132; --tx2:#6b7688; --tx3:#9aa4b4;
    --line:#e6eaf2; --sh:0 1px 2px rgba(24,33,50,.04), 0 8px 24px rgba(24,33,50,.06);
  }
  *{box-sizing:border-box}
  html,body{margin:0}
  body{
    background:var(--bg); color:var(--tx);
    font:14px/1.6 -apple-system,"Segoe UI",system-ui,"Microsoft YaHei",sans-serif;
    padding:28px 20px 120px; -webkit-font-smoothing:antialiased;
  }
  .wrap{max-width:1000px;margin:0 auto}
  h1{font-size:22px;margin:0 0 6px;letter-spacing:-.3px;display:flex;align-items:center;gap:10px}
  h1 .bg{width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#5b86ff,#3b66e8);
    display:grid;place-items:center;flex:none;box-shadow:0 4px 12px rgba(79,124,255,.35)}
  h1 .bg svg{width:16px;height:16px;stroke:#fff;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
  .sub{color:var(--tx2);font-size:13px;margin:0 0 20px;padding-left:40px}

  /* 顶栏：标题 + 退出 */
  .topbar{display:flex;align-items:center;gap:12px}
  .topbar h1{margin-bottom:0}
  .logout{
    margin-left:auto;flex:none;font-size:12.5px;color:var(--tx2);text-decoration:none;
    padding:6px 13px;border:1px solid var(--line);border-radius:8px;transition:.15s;background:var(--card);
  }
  .logout:hover{color:var(--tx);border-color:#c3cee3}

  /* 部署告警 */
  .warns{margin:0 0 16px;display:flex;flex-direction:column;gap:8px}
  .w{display:flex;gap:9px;align-items:flex-start;padding:10px 14px;border-radius:10px;font-size:12.5px;line-height:1.55}
  .w svg{flex:none;margin-top:2px}
  .w b{font-weight:600}
  .w.warn{background:rgba(240,160,32,.09);border:1px solid rgba(240,160,32,.28);color:#8a5a00}
  .w.err{background:rgba(239,74,74,.08);border:1px solid rgba(239,74,74,.26);color:#a32020}
  @media (prefers-color-scheme: dark){
    .w.warn{color:#f0b85c} .w.err{color:#ff9a9a}
  }

  /* 页脚 */
  .foot{text-align:center;font-size:11.5px;color:var(--tx3);margin:30px 0 4px;letter-spacing:.2px}

  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--sh)}
  .panel{padding:16px}
  textarea{
    width:100%;min-height:118px;resize:vertical;border:1px solid var(--line);border-radius:10px;
    background:transparent;color:var(--tx);padding:12px 14px;font:13px/1.65 ui-monospace,Consolas,"Microsoft YaHei",monospace;
    outline:none;transition:border-color .15s, box-shadow .15s;
  }
  textarea:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(79,124,255,.13)}
  textarea::placeholder{color:var(--tx3)}
  .row{display:flex;align-items:center;gap:10px;margin-top:12px;flex-wrap:wrap}
  .btn{
    appearance:none;border:1px solid var(--line);background:var(--card);color:var(--tx);
    padding:9px 16px;border-radius:9px;font-size:13px;font-weight:500;cursor:pointer;
    transition:.15s;white-space:nowrap;display:inline-flex;align-items:center;gap:7px;
  }
  .btn:hover{border-color:#c9d3e6;transform:translateY(-1px)}
  .btn:active{transform:translateY(0)}
  .btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
  .btn.primary{background:var(--acc);border-color:var(--acc);color:#fff;box-shadow:0 4px 14px rgba(79,124,255,.28)}
  .btn.primary:hover{background:var(--acc2);border-color:var(--acc2)}
  .btn.ghost{background:transparent}
  .hint{color:var(--tx3);font-size:12.5px;margin-left:auto}
  @media(max-width:640px){.hint{margin-left:0;width:100%}}

  .note{
    margin-top:14px;padding:11px 14px;border-radius:10px;font-size:12.5px;color:var(--tx2);
    background:rgba(79,124,255,.06);border:1px solid rgba(79,124,255,.16);display:flex;gap:9px;align-items:flex-start;
  }
  .note b{color:var(--tx);font-weight:600}
  .note .i{color:var(--acc);flex:none;margin-top:1px}

  .stats{display:flex;gap:18px;flex-wrap:wrap;margin:20px 2px 12px;font-size:12.5px;color:var(--tx2)}
  .stats b{color:var(--tx);font-weight:600;font-variant-numeric:tabular-nums}
  .stats .ok b{color:var(--ok)} .stats .bad b{color:var(--err)}

  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(158px,1fr));gap:14px;margin-top:6px}
  .it{
    background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;
    box-shadow:var(--sh);animation:in .28s cubic-bezier(.22,1,.36,1) both;position:relative;
  }
  @keyframes in{from{opacity:0;transform:translateY(8px) scale(.98)}to{opacity:1;transform:none}}
  .it .thumb{
    display:block;width:100%;aspect-ratio:1/1;object-fit:cover;background:
      repeating-conic-gradient(var(--line) 0% 25%, transparent 0% 50%) 50%/14px 14px;
  }
  .it .meta{padding:9px 11px 11px}
  .it .nm{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:3px}
  .it .dm{font-size:11px;color:var(--tx3);display:flex;gap:6px;font-variant-numeric:tabular-nums}
  .it .acts{display:flex;gap:6px;margin-top:8px;opacity:0;transition:.16s}
  .it:hover .acts{opacity:1}
  .it .acts a{
    flex:1;text-align:center;font-size:11.5px;padding:5px 0;border-radius:7px;text-decoration:none;
    background:rgba(79,124,255,.1);color:var(--acc);font-weight:500;transition:.13s;
  }
  .it .acts a:hover{background:var(--acc);color:#fff}
  .it .ck{
    position:absolute;left:8px;top:8px;width:20px;height:20px;border-radius:6px;cursor:pointer;
    background:rgba(255,255,255,.92);border:1px solid rgba(0,0,0,.12);display:grid;place-items:center;
    box-shadow:0 1px 4px rgba(0,0,0,.15);transition:.14s;
  }
  .it .ck svg{width:12px;height:12px;stroke:#fff;stroke-width:3;fill:none;opacity:0;transition:.14s}
  .it.sel .ck{background:var(--acc);border-color:var(--acc)}
  .it.sel .ck svg{opacity:1}
  .it.sel{border-color:var(--acc);box-shadow:0 0 0 2px rgba(79,124,255,.22),var(--sh)}

  .it.bad{display:flex;flex-direction:column;justify-content:center;padding:16px 13px;min-height:150px;
    border-style:dashed;background:transparent;box-shadow:none}
  .it.bad .t{font-size:12.5px;font-weight:600;color:var(--err);margin-bottom:4px;display:flex;align-items:center;gap:5px}
  .it.bad .u{font-size:11px;color:var(--tx3);word-break:break-all;line-height:1.5;
    display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}

  .bar{
    position:fixed;left:0;right:0;bottom:0;background:color-mix(in srgb, var(--card) 88%, transparent);
    backdrop-filter:blur(14px);border-top:1px solid var(--line);padding:12px 20px;
    display:flex;align-items:center;gap:12px;z-index:50;
    transform:translateY(102%);transition:transform .28s cubic-bezier(.22,1,.36,1);
  }
  .bar.on{transform:none}
  .bar .in{max-width:1000px;margin:0 auto;width:100%;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
  .bar .cnt{font-size:12.5px;color:var(--tx2);margin-right:auto}
  .bar .cnt b{color:var(--tx);font-variant-numeric:tabular-nums}

  .empty{text-align:center;padding:60px 20px;color:var(--tx3)}
  .empty svg{width:44px;height:44px;stroke:currentColor;fill:none;stroke-width:1.5;opacity:.5;margin-bottom:12px}
  .empty p{margin:0;font-size:13px}

  .spin{width:14px;height:14px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;
    border-radius:50%;animation:sp .7s linear infinite;display:none}
  .btn.loading .spin{display:block}
  @keyframes sp{to{transform:rotate(360deg)}}

  .toast{
    position:fixed;left:50%;bottom:84px;transform:translate(-50%,14px);opacity:0;pointer-events:none;
    background:#1e2532;color:#fff;padding:9px 16px;border-radius:9px;font-size:12.5px;
    transition:.22s;z-index:99;box-shadow:0 8px 24px rgba(0,0,0,.24);max-width:88vw;
  }
  .toast.on{opacity:1;transform:translate(-50%,0)}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <h1>
      <span class="bg"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg></span>
      云湖防盗链图片下载器
    </h1>
<?php if ((string)($CFG['password'] ?? '') !== ''): ?>
    <a class="logout" href="?a=logout">退出</a>
<?php endif; ?>
  </div>
  <p class="sub">粘贴图片链接，服务端带合法 Referer 取回，绕过 403 直接存图</p>

<?php if ($warns): ?>
  <div class="warns">
<?php foreach ($warns as $w): ?>
    <div class="w <?= $w[0] ?>">
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>
      <div><?= $w[1] ?></div>
    </div>
<?php endforeach; ?>
  </div>
<?php endif; ?>

  <div class="card panel">
    <textarea id="in" spellcheck="false" placeholder="https://chat-img.jwznb.com/xxxxxxxx.jpg&#10;https://chat-img3.jwznb.com/xxxxxxxx.webp&#10;&#10;也可以直接粘贴整段聊天记录 / 网页源码，会自动提取里面的链接"></textarea>
    <div class="row">
      <button class="btn primary" id="go"><span class="spin"></span><span>解析并下载</span></button>
      <button class="btn ghost" id="imp">导入链接文件</button>
      <input type="file" id="file" accept=".txt,.text,.md,.log,.csv,.json,.html,.htm" hidden>
<?php if ($localCount > 0): ?>
      <button class="btn ghost" id="local">载入 urls.txt（<?= (int)$localCount ?>）</button>
<?php endif; ?>
      <button class="btn ghost" id="clr">清空</button>
      <span class="hint">支持多行 · 自动去重 · 并发 6 路</span>
    </div>
    <div class="note">
      <svg class="i" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>
      <div>云湖图片服务器只认 <b>*.jwzhd.com</b> 的 Referer，浏览器直接打开或右键保存都会 403。本工具在服务端补上该请求头再转发，所以能正常拿到图。</div>
    </div>
  </div>

  <div class="stats" id="stats" hidden></div>
  <div class="grid" id="grid"></div>
  <div class="empty" id="empty">
    <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
    <p>还没有图片，先在上方粘贴链接</p>
  </div>
<?php if ($unguarded): ?>
  <div class="foot">未设访问限制 · 知道地址即可使用</div>
<?php endif; ?>
</div>

<div class="bar" id="bar">
  <div class="in">
    <span class="cnt" id="cnt"></span>
    <button class="btn ghost" id="selAll">全选</button>
    <button class="btn primary" id="zip">打包下载 ZIP</button>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const $ = (s) => document.querySelector(s);
const S = { items: [], sel: new Set(), busy: false };

function toast(msg, ms = 2200) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('on');
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.remove('on'), ms);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function fmtSize(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(2) + ' MB';
}

function render() {
  const grid = $('#grid');
  const good = S.items.filter((x) => x.ok);
  const bad = S.items.filter((x) => !x.ok);

  if (!S.items.length) {
    grid.innerHTML = '';
    $('#empty').hidden = false;
    $('#stats').hidden = true;
    $('#bar').classList.remove('on');
    return;
  }
  $('#empty').hidden = true;

  grid.innerHTML = S.items.map((x, i) => {
    if (!x.ok) {
      return `<div class="it bad">
        <div class="t">✕ ${esc(x.err || '下载失败')}</div>
        <div class="u">${esc(x.url || '')}</div>
      </div>`;
    }
    const dim = (x.w && x.h) ? `${x.w}×${x.h}` : (x.ext || '').toUpperCase();
    return `<div class="it${S.sel.has(x.key) ? ' sel' : ''}" data-k="${esc(x.key)}">
      <div class="ck" data-ck="${esc(x.key)}"><svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg></div>
      <img class="thumb" loading="lazy" src="?a=raw&k=${esc(x.key)}" alt="">
      <div class="meta">
        <div class="nm" title="${esc(x.name)}">${esc(x.name)}</div>
        <div class="dm"><span>${esc(dim)}</span><span>·</span><span>${esc(x.size || fmtSize(x.bytes))}</span></div>
        <div class="acts">
          <a href="?a=dl&k=${esc(x.key)}" download>下载</a>
          <a href="?a=raw&k=${esc(x.key)}" target="_blank" rel="noopener">原图</a>
        </div>
      </div>
    </div>`;
  }).join('');

  $('#stats').hidden = false;
  $('#stats').innerHTML = `
    <span>共 <b>${S.items.length}</b> 项</span>
    <span class="ok">成功 <b>${good.length}</b></span>
    <span class="bad">失败 <b>${bad.length}</b></span>
    ${S.lastSum ? `<span>合计 <b>${esc(S.lastSum.size)}</b></span><span>耗时 <b>${S.lastSum.ms} ms</b></span>` : ''}
    ${S.lastSum && S.lastSum.skipped ? `<span>已忽略非云湖链接 <b>${S.lastSum.skipped}</b></span>` : ''}
  `;

  $('#bar').classList.toggle('on', good.length > 0);
  $('#cnt').innerHTML = `已选 <b>${S.sel.size}</b> / ${good.length} 张`;
  $('#zip').disabled = S.sel.size === 0;
}

function syncSel() {
  document.querySelectorAll('.it[data-k]').forEach((el) => {
    el.classList.toggle('sel', S.sel.has(el.dataset.k));
  });
  const good = S.items.filter((x) => x.ok).length;
  $('#cnt').innerHTML = `已选 <b>${S.sel.size}</b> / ${good} 张`;
  $('#zip').disabled = S.sel.size === 0;
}

$('#grid').addEventListener('click', (e) => {
  const ck = e.target.closest('[data-ck]');
  const card = e.target.closest('.it[data-k]');
  if (!card) return;
  if (e.target.closest('.acts')) return;      // 点按钮不切换选中
  if (!ck && !e.target.classList.contains('thumb')) return;

  const k = card.dataset.k;
  if (S.sel.has(k)) S.sel.delete(k); else S.sel.add(k);
  syncSel();
});

async function run() {
  if (S.busy) return;
  const text = $('#in').value.trim();
  if (!text) { toast('先粘贴图片链接'); $('#in').focus(); return; }

  S.busy = true;
  const btn = $('#go');
  btn.classList.add('loading');
  btn.disabled = true;
  btn.querySelector('span:last-child').textContent = '下载中…';

  try {
    const fd = new FormData();
    fd.append('text', text);
    const r = await fetch('?a=batch', { method: 'POST', body: fd });

    // 口令过期 / 会话失效 → 回到口令页
    if (r.status === 401) { location.reload(); return; }

    const j = await r.json();

    if (!j.ok) { toast(j.error || '解析失败'); return; }

    S.items = j.items || [];
    S.lastSum = j.summary;
    S.sel = new Set(S.items.filter((x) => x.ok).map((x) => x.key));
    render();
    syncSel();

    const s = j.summary;
    toast(s.total === 0
      ? `只识别到 ${s.skipped} 个非云湖链接，已忽略`
      : `成功 ${s.success} 张，失败 ${s.fail} 张` + (s.truncated ? `（超出单次上限，还有 ${s.truncated} 个未处理）` : ''), 3200);
  } catch (err) {
    toast('请求失败：' + err.message);
  } finally {
    S.busy = false;
    btn.classList.remove('loading');
    btn.disabled = false;
    btn.querySelector('span:last-child').textContent = '解析并下载';
  }
}

$('#go').addEventListener('click', run);
$('#in').addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') run();
});

$('#clr').addEventListener('click', () => {
  $('#in').value = '';
  S.items = []; S.sel.clear(); S.lastSum = null;
  render();
});

$('#selAll').addEventListener('click', () => {
  const good = S.items.filter((x) => x.ok);
  if (S.sel.size === good.length) S.sel.clear();
  else good.forEach((x) => S.sel.add(x.key));
  syncSel();
});

$('#zip').addEventListener('click', () => {
  if (!S.sel.size) return;
  const keys = [...S.sel].join(',');
  location.href = '?a=zip&k=' + encodeURIComponent(keys);
  toast('正在打包 ' + S.sel.size + ' 张…');
});

/* 从本地文件导入链接：纯浏览器读取，不上传任何内容到服务器 */
$('#imp').addEventListener('click', () => $('#file').click());

$('#file').addEventListener('change', async (e) => {
  const el = e.target;
  const f = el.files && el.files[0];
  if (!f) return;
  if (f.size > 8 * 1024 * 1024) { toast('文件太大，建议 8MB 以内'); el.value = ''; return; }
  try {
    const text = await f.text();
    if (!text.trim()) { toast('文件是空的'); el.value = ''; return; }
    $('#in').value = text;
    toast(`已导入 ${f.name}，点「解析并下载」开始`);
  } catch (err) {
    toast('读取文件失败');
  }
  el.value = '';
});

/* 程序目录下若放了 urls.txt，提供一键载入 */
const btnLocal = $('#local');
if (btnLocal) {
  btnLocal.addEventListener('click', async () => {
    try {
      const r = await fetch('?a=local');
      const j = await r.json();
      if (!j.ok) { toast(j.error || '读取失败'); return; }
      $('#in').value = j.urls.join('\n');
      toast(`已载入 ${j.count} 个地址，点「解析并下载」开始`);
    } catch (e) { toast('读取失败'); }
  });
}

// ?q=预填链接  &auto=1 自动开始（方便把一批待下载地址做成书签）
// &theme=dark|light 强制主题（不传则跟随系统）
const Q = new URLSearchParams(location.search);
const TH = Q.get('theme');
if (TH === 'dark' || TH === 'light') document.documentElement.dataset.theme = TH;

if (Q.get('q')) {
  $('#in').value = Q.get('q');
  if (Q.get('auto') === '1') setTimeout(run, 260);
}

render();
</script>
</body>
</html>
