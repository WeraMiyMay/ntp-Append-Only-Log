#!/usr/bin/env php
<?php
declare(strict_types=1);

/*
    npt.php — CLI для append-only лога.

    Сейчас реализовано:
        init
        write --stdin
        generate --count N [--random]

*/

if (!extension_loaded('sodium')) {
    fwrite(STDERR, "Ошибка: требуется ext-sodium.\n");
    exit(1);
}

if (php_sapi_name() !== 'cli') {
    fwrite(STDERR, "Работает только в CLI.\n");
    exit(1);
}

$argv = $_SERVER['argv'];
$argc = $_SERVER['argc'];

if ($argc < 2) {
    fwrite(STDERR, "Использование: php npt.php <команда>\n");
    exit(1);
}

$command = $argv[1];

switch ($command) {

    case 'init':
        cmd_init();
        break;

    case 'write':
        cmd_write($argv);
        break;

    case 'generate':
        cmd_generate($argv);
        break;

    default:
        fwrite(STDERR, "Неизвестная команда: $command\n");
        exit(1);
}

/* --------------------------- INIT -------------------------- */

function cmd_init(): void {
    if (file_exists('data.npt')) {
        fwrite(STDERR, "Ошибка: data.npt уже существует.\n");
        exit(1);
    }
    if (file_exists('keys.json') || file_exists('allowlist.json')) {
        fwrite(STDERR, "Ошибка: keys.json или allowlist.json уже существуют.\n");
        exit(1);
    }

    file_put_contents('data.npt', '');

    $seed = random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    $keypair = sodium_crypto_sign_seed_keypair($seed);
    $pk = sodium_crypto_sign_publickey($keypair);
    $sk = sodium_crypto_sign_secretkey($keypair);

    file_put_contents('keys.json', json_encode([
        'public' => bin2hex($pk),
        'secret' => bin2hex($sk),
        'seed'   => bin2hex($seed),
        'created'=> time(),
    ], JSON_PRETTY_PRINT));

    file_put_contents('allowlist.json', json_encode([bin2hex($pk)], JSON_PRETTY_PRINT));

    fwrite(STDOUT, "init ок\n");
}

/* --------------------------- WRITE -------------------------- */

function cmd_write(array $argv): void {
    if (!in_array('--stdin', $argv, true)) {
        fwrite(STDERR, "Использование: php npt.php write --stdin\n");
        exit(1);
    }

    $payload = stream_get_contents(STDIN);
    if ($payload === false || trim($payload) === '') {
        fwrite(STDERR, "Ошибка: пустой STDIN.\n");
        exit(1);
    }

    json_decode($payload, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        fwrite(STDERR, "Ошибка: STDIN не JSON.\n");
        exit(1);
    }

    write_block($payload);
    fwrite(STDOUT, "ok\n");
}

/* ------------------------- GENERATE ------------------------- */

function cmd_generate(array $argv): void {
    $count = null;
    $randomMode = in_array('--random', $argv, true);

    foreach ($argv as $i => $a) {
        if ($a === '--count' && isset($argv[$i + 1])) {
            $count = (int)$argv[$i + 1];
        }
    }

    if ($count === null || $count <= 0) {
        fwrite(STDERR, "Использование: php npt.php generate --count N [--random]\n");
        exit(1);
    }

    for ($i = 0; $i < $count; $i++) {
        if ($randomMode) {
            $payload = json_encode([
                'id' => $i + 1,
                'ts' => time(),
                'rnd'=> bin2hex(random_bytes(4))
            ], JSON_UNESCAPED_SLASHES);
        } else {
            $payload = json_encode([
                'id' => $i + 1,
                'ts' => time()
            ], JSON_UNESCAPED_SLASHES);
        }

        write_block($payload);
    }

    fwrite(STDOUT, "Сгенерировано: $count\n");
}

/* ============================================================
 *  write_block — общая функция записи блока
 * ============================================================ */

function write_block(string $payload): void {
    $keys = json_decode(file_get_contents('keys.json'), true);
    $pk = hex2bin($keys['public']);
    $sk = hex2bin($keys['secret']);

    $allow = json_decode(file_get_contents('allowlist.json'), true);
    if (!in_array(bin2hex($pk), $allow, true)) {
        fwrite(STDERR, "Ошибка: текущий ключ не в allowlist.\n");
        exit(1);
    }

    $fh = fopen('data.npt', 'c+b');
    if (!$fh) {
        fwrite(STDERR, "Не открыть data.npt\n");
        exit(1);
    }

    $prevHash = get_last_block_hash($fh);

    $ts = time();
    $tsBytes = pack('J', $ts);
    $plen = strlen($payload);
    $plenBytes = pack('N', $plen);

    $toSign = hash('sha256', $tsBytes . $prevHash . $payload, true);
    $sig = sodium_crypto_sign_detached($toSign, $sk);

    $body =
        $tsBytes .
        $prevHash .
        $plenBytes .
        $payload .
        $pk .
        $sig;

    $LEN = pack('N', strlen($body));

    $hash = hash('sha256', $LEN . $body, true);

    $block = "NOVIJ1" . $LEN . $body . $hash;

    fseek($fh, 0, SEEK_END);
    fwrite($fh, $block);
    fclose($fh);
}

/* ---------------------- LAST BLOCK HASH --------------------- */

function get_last_block_hash($fh): string {
    fseek($fh, 0, SEEK_END);
    $size = ftell($fh);
    if ($size <= 0) {
        return str_repeat("\x00", 32);
    }

    fseek($fh, -32, SEEK_END);
    $h = fread($fh, 32);
    if ($h === false || strlen($h) !== 32) {
        return str_repeat("\x00", 32);
    }
    return $h;
}